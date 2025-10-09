#!/usr/bin/env bash

MODULE_TEMPLATE_DIR="revanced-magisk"
CWD=$(pwd)
TEMP_DIR="temp"
BIN_DIR="bin"
BUILD_DIR="build"

if [ "${GITHUB_TOKEN-}" ]; then GH_HEADER="Authorization: token ${GITHUB_TOKEN}"; else GH_HEADER=; fi
NEXT_VER_CODE=${NEXT_VER_CODE:-$(date +'%Y%m%d')}
OS=$(uname -o)

toml_prep() {
	if [ ! -f "$1" ]; then return 1; fi
	if [ "${1##*.}" == toml ]; then
		# Prefer bundled TOML binary if it runs; otherwise fallback to python-based parser
		if [ -n "${TOML-}" ] && command -v "$TOML" >/dev/null 2>&1; then
			if __TOML__=$($TOML --output json --file "$1" . 2>/dev/null); then
				:
			else
				# bundled binary exists but failed (wrong arch/format). Try python fallback below
				unset __TOML__
			fi
		fi
		if [ -z "${__TOML__-}" ]; then
			# Try python3 tomllib (py3.11+) or tomli (third-party)
			if command -v python3 >/dev/null 2>&1; then
				__TOML__=$(python3 - "$1" <<'PY'
import sys, json
fn = sys.argv[1]
try:
	import tomllib as toml
except Exception:
	try:
		import tomli as toml
	except Exception:
		sys.exit(2)
with open(fn, 'rb') as f:
	data = toml.load(f)
print(json.dumps(data))
PY
 2>/dev/null) || :
			fi
		fi
		if [ -z "${__TOML__-}" ]; then
			abort "config extension not supported or no TOML parser available (need bundled tq or python3 with tomli/tomllib)"
		fi
	elif [ "${1##*.}" == json ]; then
		__TOML__=$(cat "$1")
	else abort "config extension not supported"; fi
}
toml_get_table_names() { jq -r -e 'to_entries[] | select(.value | type == "object") | .key' <<<"$__TOML__"; }
toml_get_table_main() { jq -r -e 'to_entries | map(select(.value | type != "object")) | from_entries' <<<"$__TOML__"; }
toml_get_table() { jq -r -e ".\"${1}\"" <<<"$__TOML__"; }
toml_get() {
	local op
	op=$(jq -r ".\"${2}\" | values" <<<"$1")
	if [ "$op" ]; then
		op="${op#"${op%%[![:space:]]*}"}"
		op="${op%"${op##*[![:space:]]}"}"
		op=${op//"'"/'"'}
		echo "$op"
	else return 1; fi
}

pr() { echo -e "\033[0;32m[+] ${1}\033[0m"; }
epr() {
	echo >&2 -e "\033[0;31m[-] ${1}\033[0m"
	if [ "${GITHUB_REPOSITORY-}" ]; then echo -e "::error::utils.sh [-] ${1}\n"; fi
}
abort() {
	epr "ABORT: ${1-}"
	exit 1
}

get_rv_prebuilts() {
	local cli_src=$1 cli_ver=$2 patches_src=$3 patches_ver=$4

	# Split comma-separated patches sources
	IFS=',' read -ra patches_sources <<< "$patches_src"
	local first_patches_src="${patches_sources[0]// /}"

	pr "Getting prebuilts (${first_patches_src%/*})" >&2
	local cl_dir=${first_patches_src%/*}
	cl_dir=${TEMP_DIR}/${cl_dir,,}-rv
	mkdir -p "$cl_dir"

	local patch_files=""

	# First, get CLI
	for src_ver in "$cli_src CLI $cli_ver revanced-cli"; do
		set -- $src_ver
		local src=$1 tag=$2 ver=${3-} fprefix=$4
		local ext
		if [ "$tag" = "CLI" ]; then
			ext="jar"
			local grab_cl=false
		else abort unreachable; fi
	local dir=${src%/*}
	dir=${TEMP_DIR}/${dir,,}-rv
	mkdir -p "$dir"

		local rv_rel="https://api.github.com/repos/${src}/releases" name_ver
		if [ "$ver" = "dev" ]; then
			local resp
			resp=$(gh_req "$rv_rel" -) || return 1
			ver=$(jq -e -r '.[] | .tag_name' <<<"$resp" | get_highest_ver) || return 1
		fi
		if [ "$ver" = "latest" ]; then
			rv_rel+="/latest"
			name_ver="*"
		else
			rv_rel+="/tags/${ver}"
			name_ver="$ver"
		fi

		local url file tag_name name
		file=$(find "$dir" -name "${fprefix}-${name_ver#v}.${ext}" -type f 2>/dev/null)
		if [ -z "$file" ]; then
			local resp asset name
			resp=$(gh_req "$rv_rel" -) || return 1
			tag_name=$(jq -r '.tag_name' <<<"$resp")
			asset=$(jq -e -r ".assets[] | select(.name | endswith(\"$ext\"))" <<<"$resp") || return 1
			url=$(jq -r .url <<<"$asset")
			name=$(jq -r .name <<<"$asset")
			file="${dir}/${name}"
			gh_dl "$file" "$url" >&2 || return 1
			echo "$tag: $(cut -d/ -f1 <<<"$src")/${name}  " >>"${cl_dir}/changelog.md"
		else
			grab_cl=false
			local for_err=$file
			if [ "$ver" = "latest" ]; then
				file=$(grep -v '/[^/]*dev[^/]*$' <<<"$file" | head -1)
			else file=$(grep "/[^/]*${ver#v}[^/]*\$" <<<"$file" | head -1); fi
			if [ -z "$file" ]; then abort "filter fail: '$for_err' with '$ver'"; fi
			name=$(basename "$file")
			tag_name=$(cut -d'-' -f3- <<<"$name")
			tag_name=v${tag_name%.*}
		fi
		echo -n "$file "
	done

	# Now get patches from all sources
	for patches_source in "${patches_sources[@]}"; do
		# Trim whitespace
		patches_source="${patches_source// /}"
		if [ -z "$patches_source" ]; then continue; fi

		# Normalize common Windows-style paths so WSL can resolve them
		# Accept forms like C:\path\to\file, C:/path/to/file, /c/path/to/file
		local raw_ps="$patches_source"
		local ps
		ps="${raw_ps//\\/\/}"  # convert backslashes to slashes
		if [[ "$ps" =~ ^[A-Za-z]:/ ]]; then
			local drive="${ps:0:1}"
			local rest="${ps:2}"
			ps="/mnt/${drive,,}/${rest}"
		elif [[ "$ps" =~ ^/[A-Za-z]/ ]]; then
			local drive="${ps:1:1}"
			local rest="${ps:2}"
			ps="/mnt/${drive,,}/${rest}"
		fi

		# If the normalized path exists, prefer it; otherwise fall back to original input
		local check_path
		if [ -e "$ps" ]; then
			check_path="$ps"
		else
			check_path="$patches_source"
		fi

		# If the patches_source exists as a local file or directory, accept local patches directly
		if [ -e "$check_path" ]; then
			if [ -f "$check_path" ]; then
				case "$check_path" in
					*.rvp|*.jar)
						pr "Using local patch file: $check_path" >&2
						patch_files+="$check_path "
						echo "Local: $(basename "$check_path")" >>"${cl_dir}/changelog.md"
						continue
						;;
					*)
						pr "Skipping unsupported local file type: $check_path" >&2
						continue
						;;
				esac
			elif [ -d "$check_path" ]; then
				pr "Searching local patches in directory: $check_path" >&2
				for f in "$check_path"/*.rvp "$check_path"/*.jar; do
					[ -f "$f" ] || continue
					pr "Found local patch: $f" >&2
					patch_files+="$f "
					echo "Local: $(basename "$f")" >>"${cl_dir}/changelog.md"
				done
				continue
			fi
		fi

		for src_ver in "$patches_source Patches $patches_ver patches"; do
			set -- $src_ver
			local src=$1 tag=$2 ver=${3-} fprefix=$4
			local ext="rvp"
			local grab_cl=true

			local dir=${src%/*}
			dir=${TEMP_DIR}/${dir,,}-rv
			[ -d "$dir" ] || mkdir "$dir"

			local rv_rel="https://api.github.com/repos/${src}/releases" name_ver
			if [ "$ver" = "dev" ]; then
				local resp
				resp=$(gh_req "$rv_rel" -) || return 1
				ver=$(jq -e -r '.[] | .tag_name' <<<"$resp" | get_highest_ver) || return 1;
			fi
			if [ "$ver" = "latest" ]; then
				rv_rel+="/latest"
				name_ver="*"
			else
				rv_rel+="/tags/${ver}"
				name_ver="$ver"
			fi

			local url file tag_name name
			file=$(find "$dir" -name "${fprefix}-${name_ver#v}.${ext}" -type f 2>/dev/null)
			if [ -z "$file" ]; then
				local resp asset name
				resp=$(gh_req "$rv_rel" -) || return 1
				tag_name=$(jq -r '.tag_name' <<<"$resp")
				asset=$(jq -e -r ".assets[] | select(.name | endswith(\"$ext\"))" <<<"$resp") || return 1
				url=$(jq -r .url <<<"$asset")
				name=$(jq -r .name <<<"$asset")
				file="${dir}/${name}"
				gh_dl "$file" "$url" >&2 || return 1
				echo "$tag: $(cut -d/ -f1 <<<"$src")/${name}  " >>"${cl_dir}/changelog.md"
			else
				grab_cl=false
				local for_err=$file
				if [ "$ver" = "latest" ]; then
					file=$(grep -v '/[^/]*dev[^/]*$' <<<"$file" | head -1)
				else file=$(grep "/[^/]*${ver#v}[^/]*\$" <<<"$file" | head -1); fi
				if [ -z "$file" ]; then abort "filter fail: '$for_err' with '$ver'"; fi
				name=$(basename "$file")
				tag_name=$(cut -d'-' -f3- <<<"$name")
				tag_name=v${tag_name%.*}
			fi

			if [ $grab_cl = true ]; then echo -e "[Changelog](https://github.com/${src}/releases/tag/${tag_name})\n" >>"${cl_dir}/changelog.md"; fi
			if [ "$REMOVE_RV_INTEGRATIONS_CHECKS" = true ] && [[ "$name" == *.rvp ]]; then
				if ! (
					mkdir -p "${file}-zip" || return 1
					unzip -qo "${file}" -d "${file}-zip" || return 1
					# Only patch if the expected structure exists
					if [ -f "${file}-zip/extensions/shared.rve" ]; then
						java -cp "${BIN_DIR}/paccer.jar:${BIN_DIR}/dexlib2.jar" com.jhc.Main "${file}-zip/extensions/shared.rve" "${file}-zip/extensions/shared-patched.rve" || return 1
						mv -f "${file}-zip/extensions/shared-patched.rve" "${file}-zip/extensions/shared.rve" || return 1
					fi
					rm "${file}" || return 1
					cd "${file}-zip" || abort
					zip -0rq "${CWD}/${file}" . || return 1
				) >&2; then
					echo >&2 "Patching revanced-integrations failed"
				fi
				rm -r "${file}-zip" || :
			fi

			patch_files+="$file "
		done
	done

	echo "$patch_files"
}

set_prebuilts() {
	APKSIGNER="${BIN_DIR}/apksigner.jar"
	local arch
	arch=$(uname -m)
	if [ "$arch" = aarch64 ]; then arch=arm64; elif [ "${arch:0:5}" = "armv7" ]; then arch=arm; fi
	HTMLQ="${BIN_DIR}/htmlq/htmlq-${arch}"
	AAPT2="${BIN_DIR}/aapt2/aapt2-${arch}"
	TOML="${BIN_DIR}/toml/tq-${arch}"
}

config_update() {
	if [ ! -f build.md ]; then abort "build.md not available"; fi
	declare -A sources
	: >"$TEMP_DIR"/skipped
	local upped=()
	local prcfg=false
	for table_name in $(toml_get_table_names); do
		if [ -z "$table_name" ]; then continue; fi
		t=$(toml_get_table "$table_name")
		enabled=$(toml_get "$t" enabled) || enabled=true
		if [ "$enabled" = false ]; then continue; fi
		PATCHES_SRC=$(toml_get "$t" patches-source) || PATCHES_SRC=$DEF_PATCHES_SRC
		PATCHES_VER=$(toml_get "$t" patches-version) || PATCHES_VER=$DEF_PATCHES_VER
		if [[ -v sources["$PATCHES_SRC/$PATCHES_VER"] ]]; then
			if [ "${sources["$PATCHES_SRC/$PATCHES_VER"]}" = 1 ]; then upped+=("$table_name"); fi
		else
			sources["$PATCHES_SRC/$PATCHES_VER"]=0
			local rv_rel="https://api.github.com/repos/${PATCHES_SRC}/releases"
			if [ "$PATCHES_VER" = "dev" ]; then
				last_patches=$(gh_req "$rv_rel" - | jq -e -r '.[0]')
			elif [ "$PATCHES_VER" = "latest" ]; then
				last_patches=$(gh_req "$rv_rel/latest" -)
			else
				last_patches=$(gh_req "$rv_rel/tags/${ver}" -)
			fi
			if ! last_patches=$(jq -e -r '.assets[] | select(.name | endswith("rvp")) | .name' <<<"$last_patches"); then
				abort oops
			fi
			if [ "$last_patches" ]; then
				if ! OP=$(grep "^Patches: ${PATCHES_SRC%%/*}/" build.md | grep "$last_patches"); then
					sources["$PATCHES_SRC/$PATCHES_VER"]=1
					prcfg=true
					upped+=("$table_name")
				else
					echo "$OP" >>"$TEMP_DIR"/skipped
				fi
			fi
		fi
	done
	if [ "$prcfg" = true ]; then
		local query=""
		for table in "${upped[@]}"; do
			if [ -n "$query" ]; then query+=" or "; fi
			query+=".key == \"$table\""
		done
		jq "to_entries | map(select(${query} or (.value | type != \"object\"))) | from_entries" <<<"$__TOML__"
	fi
}

_req() {
	local ip="$1" op="$2"
	shift 2
	if [ "$op" = - ]; then
		if ! curl --tlsv1.2 -L -c "$TEMP_DIR/cookie.txt" -b "$TEMP_DIR/cookie.txt" --connect-timeout 30 --retry 0 --fail -s -S "$@" "$ip"; then
			epr "Request failed: $ip"
			return 1
		fi
	else
		if [ -f "$op" ]; then return; fi
		local dlp
		dlp="$(dirname "$op")/tmp.$(basename "$op")"
		if [ -f "$dlp" ]; then
			while [ -f "$dlp" ]; do sleep 1; done
			return
		fi
		if ! curl --tlsv1.2 -L -c "$TEMP_DIR/cookie.txt" -b "$TEMP_DIR/cookie.txt" --connect-timeout 30 --retry 0 --fail -s -S "$@" "$ip" -o "$dlp"; then
			epr "Request failed: $ip"
			return 1
		fi
		mv -f "$dlp" "$op"
	fi
}
req() { _req "$1" "$2" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0"; }
gh_req() { _req "$1" "$2" -H "$GH_HEADER"; }
gh_dl() {
	if [ ! -f "$1" ]; then
		pr "Getting '$1' from '$2'"
		_req "$2" "$1" -H "$GH_HEADER" -H "Accept: application/octet-stream"
	fi
}

log() { echo -e "$1  " >>"build.md"; }
get_highest_ver() {
	local vers m
	vers=$(tee)
	m=$(head -1 <<<"$vers")
	if ! semver_validate "$m"; then echo "$m"; else sort -rV <<<"$vers" | head -1; fi
}
semver_validate() {
	local a="${1%-*}"
	local a="${a#v}"
	local ac="${a//[.0-9]/}"
	[ ${#ac} = 0 ]
}
get_patch_last_supported_ver() {
	local list_patches=$1 pkg_name=$2 inc_sel=$3 _exc_sel=$4 _exclusive=$5 rv_cli_jar=$6 rv_patches_jars=$7
	local op
	if [ "$inc_sel" ]; then
		if ! op=$(awk '{$1=$1}1' <<<"$list_patches"); then
			epr "list-patches: '$op'"
			return 1
		fi
		local ver vers="" NL=$'\n'
		while IFS= read -r line; do
			line="${line:1:${#line}-2}"
			ver=$(sed -n "/^Name: $line\$/,/^\$/p" <<<"$op" | sed -n "/^Compatible versions:\$/,/^\$/p" | tail -n +2)
			vers=${ver}${NL}
		done <<<"$(list_args "$inc_sel")"
		vers=$(awk '{$1=$1}1' <<<"$vers")
		if [ "$vers" ]; then
			get_highest_ver <<<"$vers"
			return
		fi
	fi
	local first_patch_jar=$(echo "$rv_patches_jars" | cut -d' ' -f1)
	if ! op=$(java -jar "$rv_cli_jar" list-versions "$first_patch_jar" -f "$pkg_name" 2>&1 | tail -n +3 | awk '{$1=$1}1'); then
		epr "list-versions: '$op'"
		return 1
	fi
	if [ "$op" = "Any" ]; then return; fi
	pcount=$(head -1 <<<"$op") pcount=${pcount#*(} pcount=${pcount% *}
	if [ -z "$pcount" ]; then
		return 0
	fi
	grep -F "($pcount patch" <<<"$op" | sed 's/ (.* patch.*//' | get_highest_ver || return 1
}

isoneof() {
	local i=$1 v
	shift
	for v; do [ "$v" = "$i" ] && return 0; done
	return 1
}

merge_splits() {
	local bundle=$1 output=$2
	pr "Merging splits"
	gh_dl "$TEMP_DIR/apkeditor.jar" "https://github.com/REAndroid/APKEditor/releases/download/V1.4.5/APKEditor-1.4.5.jar" >/dev/null || return 1
	if ! OP=$(java -jar "$TEMP_DIR/apkeditor.jar" merge -i "${bundle}" -o "${bundle}.mzip" -clean-meta -f 2>&1); then
		# Save full apkeditor output to a log for debugging, but show a concise message to the user
		mkdir -p "$TEMP_DIR" || :
		log_file="$TEMP_DIR/$(basename "${bundle}").apkeditor.log"
		printf '%s
' "$OP" >"$log_file" 2>/dev/null || :
		pr "Apkeditor failed to merge '${bundle}' (see: ${log_file}). Attempting unzip-based fallback."
		# Apkeditor sometimes fails on certain bundle formats. Try a simple unzip-based fallback:
		pr "Attempting fallback merge for ${bundle} (unzip-based)"
		mkdir -p "${bundle}-zip-fallback"
		if unzip -qo "${bundle}" -d "${bundle}-zip-fallback" 2>/dev/null || unzip -qo "${bundle}.apkm" -d "${bundle}-zip-fallback" 2>/dev/null; then
			# search recursively for any apk files inside the extracted folder
			mapfile -t apks < <(find "${bundle}-zip-fallback" -type f -iname "*.apk" 2>/dev/null || true)
			if (( ${#apks[@]} )); then
				if (( ${#apks[@]} == 1 )); then
					pr "Fallback: found single APK ${apks[0]}, using it as output"
					cp -f "${apks[0]}" "${output}"
					rm -rf "${bundle}-zip-fallback"
					return 0
				else
					pr "Fallback: found ${#apks[@]} APK files, zipping extracted contents"
					(cd "${bundle}-zip-fallback" && zip -0rq "${CWD}/${bundle}.zip" .)
					if isoneof "module" "${build_mode_arr[@]}"; then
						patch_apk "${bundle}.zip" "${output}" "--exclusive" "${args[cli]}" "${args[ptjar]}"
						local ret=$?
					else
						cp "${bundle}.zip" "${output}"
						local ret=$?
					fi
					rm -rf "${bundle}-zip-fallback" "${bundle}.zip" || :
					return $ret
				fi
			else
				# No nested .apk files; check if the extracted folder looks like an APK contents
				if find "${bundle}-zip-fallback" -maxdepth 1 -type f \( -iname "classes.dex" -o -iname "AndroidManifest.xml" \) | read -r _; then
					pr "Fallback: archive contains APK contents (classes.dex/AndroidManifest.xml). Zipping contents."
					(cd "${bundle}-zip-fallback" && zip -0rq "${CWD}/${bundle}.zip" .)
					if isoneof "module" "${build_mode_arr[@]}"; then
						patch_apk "${bundle}.zip" "${output}" "--exclusive" "${args[cli]}" "${args[ptjar]}"
						local ret=$?
					else
						cp "${bundle}.zip" "${output}"
						local ret=$?
					fi
					rm -rf "${bundle}-zip-fallback" "${bundle}.zip" || :
					return $ret
				else
					epr "Fallback: no .apk files found inside ${bundle}"
					rm -rf "${bundle}-zip-fallback"
					return 1
				fi
			fi
		else
			epr "Fallback unzip failed for ${bundle}"
			rm -rf "${bundle}-zip-fallback"
			return 1
		fi
	fi
	# this is required because of apksig
	mkdir "${bundle}-zip"
	unzip -qo "${bundle}.mzip" -d "${bundle}-zip"
	(
		cd "${bundle}-zip" || abort
		zip -0rq "${CWD}/${bundle}.zip" .
	)
	# if building module, sign the merged apk properly
	if isoneof "module" "${build_mode_arr[@]}"; then
		patch_apk "${bundle}.zip" "${output}" "--exclusive" "${args[cli]}" "${args[ptjar]}"
		local ret=$?
	else
		cp "${bundle}.zip" "${output}"
		local ret=$?
	fi
	rm -r "${bundle}-zip" "${bundle}.zip" "${bundle}.mzip" || :
	return $ret
}

# -------------------- apkmirror --------------------
apk_mirror_search() {
	local resp="$1" dpi="$2" arch="$3" apk_bundle="$4"
	local apparch dlurl node app_table
	if [ "$arch" = all ]; then
		apparch=(universal noarch 'arm64-v8a + armeabi-v7a')
	else apparch=("$arch" universal noarch 'arm64-v8a + armeabi-v7a'); fi
	for ((n = 1; n < 40; n++)); do
		node=$($HTMLQ "div.table-row.headerFont:nth-last-child($n)" -r "span:nth-child(n+3)" <<<"$resp")
		if [ -z "$node" ]; then break; fi
		app_table=$($HTMLQ --text --ignore-whitespace <<<"$node")
		if [ "$(sed -n 3p <<<"$app_table")" = "$apk_bundle" ] && [ "$(sed -n 6p <<<"$app_table")" = "$dpi" ] &&
			isoneof "$(sed -n 4p <<<"$app_table")" "${apparch[@]}"; then
			dlurl=$($HTMLQ --base https://www.apkmirror.com --attribute href "div:nth-child(1) > a:nth-child(1)" <<<"$node")
			echo "$dlurl"
			return 0
		fi
	done
	return 1
}
dl_apkmirror() {
	local url=$1 version=${2// /-} output=$3 arch=$4 dpi=$5 is_bundle=false
	if [ -f "${output}.apkm" ]; then
		is_bundle=true
	else
		if [ "$arch" = "arm-v7a" ]; then arch="armeabi-v7a"; fi
		local resp node app_table apkmname dlurl=""
		apkmname=$($HTMLQ "h1.marginZero" --text <<<"$__APKMIRROR_RESP__")
		apkmname="${apkmname,,}" apkmname="${apkmname// /-}" apkmname="${apkmname//[^a-z0-9-]/}"
		url="${url}/${apkmname}-${version//./-}-release/"
		resp=$(req "$url" -) || return 1
		node=$($HTMLQ "div.table-row.headerFont:nth-last-child(1)" -r "span:nth-child(n+3)" <<<"$resp")
		if [ "$node" ]; then
			if ! dlurl=$(apk_mirror_search "$resp" "$dpi" "${arch}" "APK"); then
				if ! dlurl=$(apk_mirror_search "$resp" "$dpi" "${arch}" "BUNDLE"); then
					return 1
				else is_bundle=true; fi
			fi
			[ -z "$dlurl" ] && return 1
			resp=$(req "$dlurl" -)
		fi
		url=$(echo "$resp" | $HTMLQ --base https://www.apkmirror.com --attribute href "a.btn") || return 1
		url=$(req "$url" - | $HTMLQ --base https://www.apkmirror.com --attribute href "span > a[rel = nofollow]") || return 1
	fi

	if [ "$is_bundle" = true ]; then
		req "$url" "${output}.apkm" || return 1
		merge_splits "${output}.apkm" "${output}"
	else
		req "$url" "${output}" || return 1
	fi
}
get_apkmirror_vers() {
	local vers apkm_resp
	apkm_resp=$(req "https://www.apkmirror.com/uploads/?appcategory=${__APKMIRROR_CAT__}" -)
	vers=$(sed -n 's;.*Version:</span><span class="infoSlide-value">\(.*\) </span>.*;\1;p' <<<"$apkm_resp" | awk '{$1=$1}1')
	if [ "$__AAV__" = false ]; then
		local IFS=$'\n'
		vers=$(grep -iv "\(beta\|alpha\)" <<<"$vers")
		local v r_vers=()
		for v in $vers; do
			grep -iq "${v} \(beta\|alpha\)" <<<"$apkm_resp" || r_vers+=("$v")
		done
		echo "${r_vers[*]}"
	else
		echo "$vers"
	fi
}
get_apkmirror_pkg_name() { sed -n 's;.*id=\(.*\)" class="accent_color.*;\1;p' <<<"$__APKMIRROR_RESP__"; }
get_apkmirror_resp() {
	__APKMIRROR_RESP__=$(req "${1}" -)
	__APKMIRROR_CAT__="${1##*/}"
}

# -------------------- uptodown --------------------
get_uptodown_resp() {
	__UPTODOWN_RESP__=$(req "${1}/versions" -)
	__UPTODOWN_RESP_PKG__=$(req "${1}/download" -)
}
get_uptodown_vers() { $HTMLQ --text ".version" <<<"$__UPTODOWN_RESP__"; }
dl_uptodown() {
	local uptodown_dlurl=$1 version=$2 output=$3 arch=$4 _dpi=$5
	local apparch
	if [ "$arch" = "arm-v7a" ]; then arch="armeabi-v7a"; fi
	if [ "$arch" = all ]; then
		apparch=('arm64-v8a, armeabi-v7a, x86, x86_64' 'arm64-v8a, armeabi-v7a')
	else apparch=("$arch" 'arm64-v8a, armeabi-v7a, x86, x86_64' 'arm64-v8a, armeabi-v7a'); fi

	local op resp data_code
	data_code=$($HTMLQ "#detail-app-name" --attribute data-code <<<"$__UPTODOWN_RESP__")
	local versionURL=""
	local is_bundle=false
	for i in {1..5}; do
		resp=$(req "${uptodown_dlurl}/apps/${data_code}/versions/${i}" -)
		if ! op=$(jq -e -r ".data | map(select(.version == \"${version}\")) | .[0]" <<<"$resp"); then
			continue
		fi
		if [ "$(jq -e -r ".kindFile" <<<"$op")" = "xapk" ]; then is_bundle=true; fi
		if versionURL=$(jq -e -r '.versionURL' <<<"$op"); then break; else return 1; fi
	done
	if [ -z "$versionURL" ]; then return 1; fi
	versionURL=$(jq -e -r '.url + "/" + .extraURL + "/" + (.versionID | tostring)' <<<"$versionURL")
	resp=$(req "$versionURL" -) || return 1

	local data_version files node_arch data_file_id
	data_version=$($HTMLQ '.button.variants' --attribute data-version <<<"$resp") || return 1
	if [ "$data_version" ]; then
		files=$(req "${uptodown_dlurl%/*}/app/${data_code}/version/${data_version}/files" - | jq -e -r .content) || return 1
		for ((n = 1; n < 12; n += 2)); do
			node_arch=$($HTMLQ ".content > p:nth-child($n)" --text <<<"$files" | xargs) || return 1
			if [ -z "$node_arch" ]; then return 1; fi
			if ! isoneof "$node_arch" "${apparch[@]}"; then continue; fi
			data_file_id=$($HTMLQ "div.variant:nth-child($((n + 1))) > .v-report" --attribute data-file-id <<<"$files") || return 1
			resp=$(req "${uptodown_dlurl}/download/${data_file_id}-x" -)
			break
		done
	fi
	local data_url
	data_url=$($HTMLQ "#detail-download-button" --attribute data-url <<<"$resp") || return 1
	if [ $is_bundle = true ]; then
		req "https://dw.uptodown.com/dwn/${data_url}" "$output.apkm" || return 1
		# sanity check: ensure the downloaded file is an archive and not an HTML error page
		if grep -Iq "<html" "$output.apkm" 2>/dev/null; then
			epr "Downloaded Uptodown bundle appears to be an HTML page (download failed or blocked)."
			return 1
		fi
		merge_splits "${output}.apkm" "${output}"
	else
		req "https://dw.uptodown.com/dwn/${data_url}" "$output"
	fi
}
get_uptodown_pkg_name() { $HTMLQ --text "tr.full:nth-child(1) > td:nth-child(3)" <<<"$__UPTODOWN_RESP_PKG__"; }

# -------------------- apkpure --------------------
get_apkpure_resp() {
	# Extract package name from URL pattern: https://apkpure.com/app-name/com.package.name
	__APKPURE_PKG_NAME__=$(echo "${1}" | sed -n 's;.*/\([a-z0-9._]*\)$;\1;p')
	if [ -z "$__APKPURE_PKG_NAME__" ]; then
		epr "Could not extract package name from APKPure URL: ${1}"
		return 1
	fi
	# We don't need to fetch the page since we can extract package from URL
	__APKPURE_RESP__="ok"
}
get_apkpure_vers() {
	# APKPure blocks automated requests, so we can't reliably list versions
	# If we previously detected an actual version, return it; otherwise return "latest"
	if [ -n "${__APKPURE_ACTUAL_VERSION__-}" ]; then
		echo "$__APKPURE_ACTUAL_VERSION__"
	else
		echo "latest"
	fi
}
dl_apkpure() {
	local apkpure_dlurl=$1 version=$2 output=$3 arch=$4 _dpi=$5
	local download_url pkg_name ver_param

	# Extract package name from the stored response
	pkg_name="$__APKPURE_PKG_NAME__"
	if [ -z "$pkg_name" ]; then
		epr "Could not extract package name from APKPure"
		return 1
	fi

	# Set version parameter
	if [ "$version" = "latest" ] || [ -z "$version" ]; then
		ver_param="latest"
	else
		ver_param="${version}"
	fi

	local temp_dl="${output}.tmp"
	local download_success=false
	local tried_formats=()

	# APKPure-specific download function (without --fail flag to handle redirects better)
	apkpure_dl() {
		local url=$1 out=$2
		# Remove --fail flag for APKPure downloads as they use multiple redirects
		if curl --tlsv1.2 -L -c "$TEMP_DIR/cookie.txt" -b "$TEMP_DIR/cookie.txt" --connect-timeout 30 --retry 2 -s -S \
			-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0" \
			"$url" -o "$out" 2>/dev/null; then
			# Verify we got actual data (file size > 1KB)
			if [ -f "$out" ] && [ $(stat -c%s "$out" 2>/dev/null || stat -f%z "$out" 2>/dev/null) -gt 1024 ]; then
				return 0
			fi
		fi
		return 1
	}

	# Try XAPK endpoint first (bundles are more common for newer apps)
	download_url="https://d.apkpure.com/b/XAPK/${pkg_name}?version=${ver_param}"
	pr "Trying APKPure XAPK: $download_url"
	if apkpure_dl "$download_url" "$temp_dl"; then
		# Verify it's a valid download (not an error page)
		if file "$temp_dl" 2>/dev/null | grep -qi "zip\|android"; then
			download_success=true
			tried_formats+=("XAPK")
		else
			rm -f "$temp_dl"
			tried_formats+=("XAPK (invalid)")
		fi
	else
		rm -f "$temp_dl"
		tried_formats+=("XAPK (failed)")
	fi

	# If XAPK failed, try APK endpoint
	if [ "$download_success" = false ]; then
		download_url="https://d.apkpure.com/b/APK/${pkg_name}?version=${ver_param}"
		pr "Trying APKPure APK: $download_url"
		if apkpure_dl "$download_url" "$temp_dl"; then
			# Verify it's a valid download
			if file "$temp_dl" 2>/dev/null | grep -qi "zip\|android"; then
				download_success=true
				tried_formats+=("APK")
			else
				rm -f "$temp_dl"
				tried_formats+=("APK (invalid)")
			fi
		else
			rm -f "$temp_dl"
			tried_formats+=("APK (failed)")
		fi
	fi

	# If both failed, return error
	if [ "$download_success" = false ]; then
		epr "APKPure download failed for ${pkg_name}. Tried: ${tried_formats[*]}"
		return 1
	fi

	# Detect file type by checking magic bytes and content
	local file_type=""
	if file "$temp_dl" 2>/dev/null | grep -qi "zip"; then
		# Check if it's a bundle (XAPK/APKM) or just a plain APK in zip format
		if unzip -l "$temp_dl" 2>/dev/null | grep -qi "\.apk"; then
			file_type="bundle"
		else
			file_type="apk"
		fi
	elif file "$temp_dl" 2>/dev/null | grep -qi "apk\|android"; then
		file_type="apk"
	else
		# Fallback: check if it's a valid zip (bundles are zips)
		if unzip -t "$temp_dl" >/dev/null 2>&1; then
			file_type="bundle"
		else
			file_type="apk"
		fi
	fi

	pr "APKPure download successful (${tried_formats[-1]}, detected as ${file_type})"

	# If version was "latest", try to extract actual version before processing
	local actual_version=""
	if [ "$ver_param" = "latest" ]; then
		if [ "$file_type" = "bundle" ]; then
			# For bundles (XAPK), extract version from manifest.json
			actual_version=$(unzip -p "$temp_dl" manifest.json 2>/dev/null | jq -r '.version_name // .versionName // empty' 2>/dev/null || echo "")
		fi

		if [ -n "$actual_version" ]; then
			pr "Detected actual version from bundle manifest: $actual_version"
			# Update output path to use actual version
			local base_output="${output%-latest-*}"
			local suffix="${output##*-latest-}"
			output="${base_output}-${actual_version}-${suffix}"
			__APKPURE_ACTUAL_VERSION__="$actual_version"
		fi
	fi

	if [ "$file_type" = "bundle" ]; then
		# It's a bundle (xapk/apks/apkm/zip) - merge it
		mv "$temp_dl" "${output}.apkm"
		if ! merge_splits "${output}.apkm" "$output"; then
			epr "Failed to merge APKPure bundle"
			rm -f "${output}.apkm"
			return 1
		fi
	else
		# It's a plain APK
		mv "$temp_dl" "$output"
	fi

	return 0
}
get_apkpure_pkg_name() { echo "$__APKPURE_PKG_NAME__"; }

# -------------------- archive --------------------
dl_archive() {
	local url=$1 version=$2 output=$3 arch=$4
	local path version=${version// /}
	path=$(grep "${version_f#v}-${arch// /}" <<<"$__ARCHIVE_RESP__") || return 1
	req "${url}/${path}" "$output"
}
get_archive_resp() {
	local r
	r=$(req "$1" -)
	if [ -z "$r" ]; then return 1; else __ARCHIVE_RESP__=$(sed -n 's;^<a href="\(.*\)"[^"]*;\1;p' <<<"$r"); fi
	__ARCHIVE_PKG_NAME__=$(awk -F/ '{print $NF}' <<<"$1")
}
get_archive_vers() { sed 's/^[^-]*-//;s/-\(all\|arm64-v8a\|arm-v7a\)\.apk//g' <<<"$__ARCHIVE_RESP__"; }
get_archive_pkg_name() { echo "$__ARCHIVE_PKG_NAME__"; }
# --------------------------------------------------

patch_apk() {
	local stock_input=$1 patched_apk=$2 patcher_args=$3 rv_cli_jar=$4 rv_patches_jars=$5

	# Handle multiple patch files separated by spaces
	local patch_params=""
	for patch_file in $rv_patches_jars; do
		if [ -f "$patch_file" ]; then
			patch_params+="-b $patch_file "
		fi
	done

	local cmd="env -u GITHUB_REPOSITORY java -jar $rv_cli_jar patch $stock_input -p -o $patched_apk $patch_params --keystore=ks.keystore \
--keystore-entry-password=123456789 --keystore-password=123456789 --signer=jhc --keystore-entry-alias=jhc $patcher_args"
	if [ "$OS" = Android ]; then cmd+=" --custom-aapt2-binary=${AAPT2}"; fi
	pr "$cmd"
	if eval "$cmd"; then [ -f "$patched_apk" ]; else
		rm "$patched_apk" 2>/dev/null || :
		return 1
	fi
}

check_sig() {
	local file=$1 pkg_name=$2
	local sig
	if grep -q "$pkg_name" sig.txt; then
		# Get all signatures from the APK (apps can have multiple signers)
		local sigs
		sigs=$(java -jar "$APKSIGNER" verify --print-certs "$file" 2>&1 | grep "^Signer.*certificate SHA-256 digest:" | awk '{print $NF}')

		# Check if any signature matches
		local found=false
		while IFS= read -r sig; do
			if [ -n "$sig" ] && grep -qFx "$sig $pkg_name" sig.txt; then
				found=true
				break
			fi
		done <<<"$sigs"

		# If no match found, add all new signatures
		if [ "$found" = false ]; then
			pr "Adding new signature(s) for $pkg_name to sig.txt"
			while IFS= read -r sig; do
				if [ -n "$sig" ] && ! grep -qFx "$sig $pkg_name" sig.txt; then
					echo "$sig $pkg_name" >> sig.txt
					pr "Added: $sig"
				fi
			done <<<"$sigs"
		fi

		return 0
	fi
}

build_rv() {
	eval "declare -A args=${1#*=}"
	local version="" pkg_name=""
	local mode_arg=${args[build_mode]} version_mode=${args[version]}
	local app_name=${args[app_name]}
	local app_name_l=${app_name,,}
	app_name_l=${app_name_l// /-}
	local table=${args[table]}
	local dl_from=${args[dl_from]}
	local arch=${args[arch]}
	local arch_f="${arch// /}"

	local p_patcher_args=()
	if [ "${args[excluded_patches]}" ]; then p_patcher_args+=("$(join_args "${args[excluded_patches]}" -d)"); fi
	if [ "${args[included_patches]}" ]; then p_patcher_args+=("$(join_args "${args[included_patches]}" -e)"); fi
	[ "${args[exclusive_patches]}" = true ] && p_patcher_args+=("--exclusive")

	local tried_dl=()
	for dl_p in archive apkmirror apkpure uptodown; do
		if [ -z "${args[${dl_p}_dlurl]}" ]; then continue; fi
		if ! get_${dl_p}_resp "${args[${dl_p}_dlurl]}" || ! pkg_name=$(get_"${dl_p}"_pkg_name); then
			args[${dl_p}_dlurl]=""
			epr "ERROR: Could not find ${table} in ${dl_p}"
			continue
		fi
		tried_dl+=("$dl_p")
		dl_from=$dl_p
		break
	done
	if [ -z "$pkg_name" ]; then
		epr "empty pkg name, not building ${table}."
		return 0
	fi
	local list_patches
	# Use the first patch file for querying patch information
	local first_patch_jar=$(echo ${args[ptjar]} | cut -d' ' -f1)
	list_patches=$(java -jar "${args[cli]}" list-patches "$first_patch_jar" -f "$pkg_name" -v -p 2>&1)

	local get_latest_ver=false
	if [ "$version_mode" = auto ]; then
		if ! version=$(get_patch_last_supported_ver "$list_patches" "$pkg_name" \
			"${args[included_patches]}" "${args[excluded_patches]}" "${args[exclusive_patches]}" "${args[cli]}" "$first_patch_jar"); then
			exit 1
		elif [ -z "$version" ]; then get_latest_ver=true; fi
	elif isoneof "$version_mode" latest beta; then
		get_latest_ver=true
		p_patcher_args+=("-f")
	else
		version=$version_mode
		p_patcher_args+=("-f")
	fi
	if [ $get_latest_ver = true ]; then
		if [ "$version_mode" = beta ]; then __AAV__="true"; else __AAV__="false"; fi
		pkgvers=$(get_"${dl_from}"_vers)
		version=$(get_highest_ver <<<"$pkgvers") || version=$(head -1 <<<"$pkgvers")
	fi
	if [ -z "$version" ]; then
		epr "empty version, not building ${table}."
		return 0
	fi

	if [ "$mode_arg" = module ]; then
		build_mode_arr=(module)
	elif [ "$mode_arg" = apk ]; then
		build_mode_arr=(apk)
	elif [ "$mode_arg" = both ]; then
		build_mode_arr=(apk module)
	fi

	pr "Choosing version '${version}' for ${table}"
	local version_f=${version// /}
	version_f=${version_f#v}
	local stock_apk="${TEMP_DIR}/${pkg_name}-${version_f}-${arch_f}.apk"
	if [ ! -f "$stock_apk" ]; then
		for dl_p in archive apkmirror apkpure uptodown; do
			if [ -z "${args[${dl_p}_dlurl]}" ]; then continue; fi
			pr "Downloading '${table}' from ${dl_p}"
			if ! isoneof $dl_p "${tried_dl[@]}"; then get_${dl_p}_resp "${args[${dl_p}_dlurl]}"; fi
			if ! dl_${dl_p} "${args[${dl_p}_dlurl]}" "$version" "$stock_apk" "$arch" "${args[dpi]}" "$get_latest_ver"; then
				epr "ERROR: Could not download '${table}' from ${dl_p} with version '${version}', arch '${arch}', dpi '${args[dpi]}'"
				continue
			fi
			# If APKPure downloaded with "latest" and extracted actual version, update our version variable
			if [ "$dl_p" = "apkpure" ] && [ -n "${__APKPURE_ACTUAL_VERSION__-}" ]; then
				version="${__APKPURE_ACTUAL_VERSION__}"
				version_f=${version// /}
				version_f=${version_f#v}
				stock_apk="${TEMP_DIR}/${pkg_name}-${version_f}-${arch_f}.apk"
				unset __APKPURE_ACTUAL_VERSION__
			fi
			break
		done
		# If downloads failed, try a local fallback APK in $TEMP_DIR
		if [ ! -f "$stock_apk" ]; then
			# try to find candidate APKs in TEMP_DIR matching pkg_name and arch
			mapfile -t _cands < <(find "$TEMP_DIR" -maxdepth 2 -type f \( -iname "${pkg_name}-*-${arch_f}.apk" -o -iname "${pkg_name}*${arch_f}*.apk" \) 2>/dev/null || true)
			if (( ${#_cands[@]} )); then
				# pick the newest by mtime
				stock_apk=$(printf '%s
' "${_cands[@]}" | xargs -d '\n' ls -1t 2>/dev/null | head -n1)
				pr "Using local fallback APK: $stock_apk"
				# try to derive version from filename e.g. pkgname-6.50.2-arm64-v8a.apk
				base=$(basename "$stock_apk")
				version_from_file=$(sed -n "s/^${pkg_name}-\(.*\)-${arch_f}.*$/\1/p" <<<"$base") || :
				if [ -n "$version_from_file" ]; then
					version="$version_from_file"
					version_f=${version// /}
					version_f=${version_f#v}
				fi
			else
				return 0
			fi
		fi
	fi
	if ! OP=$(check_sig "$stock_apk" "$pkg_name" 2>&1) && ! grep -qFx "ERROR: Missing META-INF/MANIFEST.MF" <<<"$OP"; then
		abort "apk signature mismatch '$stock_apk': $OP"
	fi
	log "${table}: ${version}"

	local microg_patch
	microg_patch=$(grep "^Name: " <<<"$list_patches" | grep -i "gmscore\|microg" || :) microg_patch=${microg_patch#*: }
	if [ -n "$microg_patch" ] && [[ ${p_patcher_args[*]} =~ $microg_patch ]]; then
		epr "You cant include/exclude microg patch as that's done by rvmm builder automatically."
		p_patcher_args=("${p_patcher_args[@]//-[ei] ${microg_patch}/}")
	fi

	local spoof_client_patch
	spoof_client_patch=$(grep "^Name: " <<<"$list_patches" | grep -i "Spoof Client" || :) spoof_client_patch=${spoof_client_patch#*: }
	local spoof_video_patch
	spoof_video_patch=$(grep "^Name: " <<<"$list_patches" | grep -i "Spoof Video" || :) spoof_video_patch=${spoof_video_patch#*: }

	local patcher_args patched_apk build_mode
	local rv_brand_f=${args[rv_brand],,}
	rv_brand_f=${rv_brand_f// /-}
	if [ "${args[patcher_args]}" ]; then p_patcher_args+=("${args[patcher_args]}"); fi
	for build_mode in "${build_mode_arr[@]}"; do
		patcher_args=("${p_patcher_args[@]}")
		pr "Building '${table}' in '$build_mode' mode"
		if [ -n "$microg_patch" ]; then
			patched_apk="${TEMP_DIR}/${app_name_l}-${rv_brand_f}-${version_f}-${arch_f}-${build_mode}.apk"
		else
			patched_apk="${TEMP_DIR}/${app_name_l}-${rv_brand_f}-${version_f}-${arch_f}.apk"
		fi
		if [ -n "$microg_patch" ]; then
			if [ "$build_mode" = apk ]; then
				patcher_args+=("-e \"${microg_patch}\"")
			elif [ "$build_mode" = module ]; then
				patcher_args+=("-d \"${microg_patch}\"")
			fi
		fi
		if [ -n "$spoof_client_patch" ] && [[ ! ${p_patcher_args[*]} =~ $spoof_client_patch ]] && [ "$build_mode" = module ]; then
			patcher_args+=("-d \"${spoof_client_patch}\"")
		fi
		if [ -n "$spoof_video_patch" ] && [[ ! ${p_patcher_args[*]} =~ $spoof_video_patch ]] && [ "$build_mode" = module ]; then
			patcher_args+=("-d \"${spoof_video_patch}\"")
		fi
		if [ "${args[riplib]}" = true ]; then
			patcher_args+=("--rip-lib x86_64 --rip-lib x86")
			if [ "$build_mode" = module ]; then
				patcher_args+=("--rip-lib arm64-v8a --rip-lib armeabi-v7a --unsigned")
			else
				if [ "$arch" = "arm64-v8a" ]; then
					patcher_args+=("--rip-lib armeabi-v7a")
				elif [ "$arch" = "arm-v7a" ]; then
					patcher_args+=("--rip-lib arm64-v8a")
				fi
			fi
		fi
		if [ "${NORB:-}" != true ] || [ ! -f "$patched_apk" ]; then
			if ! patch_apk "$stock_apk" "$patched_apk" "${patcher_args[*]}" "${args[cli]}" "${args[ptjar]}"; then
				epr "Building '${table}' failed!"
				return 0
			fi
		fi
		if [ "$build_mode" = apk ]; then
			local apk_output="${BUILD_DIR}/${app_name_l}-${rv_brand_f}-v${version_f}-${arch_f}.apk"
			mv -f "$patched_apk" "$apk_output"
			pr "Built ${table} (non-root): '${apk_output}'"
			continue
		fi
		local base_template
		base_template=$(mktemp -d -p "$TEMP_DIR")
		cp -a $MODULE_TEMPLATE_DIR/. "$base_template"
		local upj="${table,,}-update.json"

		module_config "$base_template" "$pkg_name" "$version" "$arch"

		local rv_patches_ver="${first_patch_jar##*-}"
		module_prop \
			"${args[module_prop_name]}" \
			"${app_name} ${args[rv_brand]}" \
			"${version} (patches ${rv_patches_ver%%.rvp})" \
			"${app_name} ${args[rv_brand]} Magisk module" \
			"https://raw.githubusercontent.com/${GITHUB_REPOSITORY-}/update/${upj}" \
			"$base_template"

		local module_output="${app_name_l}-${rv_brand_f}-magisk-v${version_f}-${arch_f}.zip"
		pr "Packing module ${table}"
		cp -f "$patched_apk" "${base_template}/base.apk"
		if [ "${args[include_stock]}" = true ]; then cp -f "$stock_apk" "${base_template}/${pkg_name}.apk"; fi
		pushd >/dev/null "$base_template" || abort "Module template dir not found"
		zip -"$COMPRESSION_LEVEL" -FSqr "${CWD}/${BUILD_DIR}/${module_output}" .
		popd >/dev/null || :
		pr "Built ${table} (root): '${BUILD_DIR}/${module_output}'"
	done
}

list_args() { tr -d '\t\r' <<<"$1" | tr -s ' ' | sed 's/" "/"\n"/g' | sed 's/\([^"]\)"\([^"]\)/\1'\''\2/g' | grep -v '^$' || :; }
join_args() { list_args "$1" | sed "s/^/${2} /" | paste -sd " " - || :; }

module_config() {
	local ma=""
	if [ "$4" = "arm64-v8a" ]; then
		ma="arm64"
	elif [ "$4" = "arm-v7a" ]; then
		ma="arm"
	fi
	echo "PKG_NAME=$2
PKG_VER=$3
MODULE_ARCH=$ma" >"$1/config"
}
module_prop() {
	echo "id=${1}
name=${2}
version=v${3}
versionCode=${NEXT_VER_CODE}
author=j-hc
description=${4}" >"${6}/module.prop"

	if [ "$ENABLE_MAGISK_UPDATE" = true ]; then echo "updateJson=${5}" >>"${6}/module.prop"; fi
}
