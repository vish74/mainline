#!/bin/bash

set -e

#DIALOG=Xdialog --default-no
DIALOG=kdialog

ROOT_PATH=""

#
# compatible with obexpushd >= 0.6
#

MODE="$1"
FROM=""
NAME=""
SUB_PATH="${ROOT_PATH}."
LENGTH="0"
while read LINE; do
	if ( test -z "${LINE}" ); then
		break
	fi
	TAG=$(echo "${LINE}" | cut -f 1 -d ":")
	VALUE=$(echo "${LINE}" | cut -f 2- -d " ")
	case $TAG in
	From)   FROM="${VALUE}";;
	Name)   NAME="${VALUE}";;
	Path)   SUB_PATH="${ROOT_PATH}${VALUE}/";;
	Length) LENGTH="${VALUE}";;
	esac
done

case "${MODE}" in
put)
	test "${NAME}" || exit 1
	test -e "${NAME}" && exit 1

	#tell obexpushd to go on
	${DIALOG} --title "Obex-Push" \
            --yesno \
            "Allow receiving the file\n\"${SUB_PATH}${NAME}\"\n(${LENGTH} bytes) from\n${FROM}" \
            10 40
	if ( test "$?" -eq "0" ); then
		echo "OK"
	else
		echo "ABORT"
		exit 1
	fi

	cat > "${SUB_PATH}${NAME}"
	;;

get)
	test "${SUB_PATH}${NAME}" || exit 1
	test -f "${SUB_PATH}${NAME}" || exit 1

	FILE=${NAME}
	stat --printf="Length: %s\n" ${NAME}
	stat --format="%y" "${SUB_PATH}${NAME}" | date -u +"Time: %Y%m%dT%H%M%SZ"
	echo ""
	cat "${SUB_PATH}${NAME}"
	;;

listdir)
	FILE=$(mktemp)
	obex-folder-listing ${SUB_PATH} >${FILE} 2>/dev/null
	stat --printf="Length: %s\n" ${FILE}
	echo ""
	cat ${FILE}
	rm -f ${FILE}
	;;

capability)
	;;
esac
exit 0
