#!/bin/sh

#DIALOG=Xdialog --default-no
DIALOG=kdialog

#
# compatible with obexpushd 0.6
#

MODE="$1"
FROM=""
NAME=""
LENGTH="0"
TYPE=""
while read LINE; do
    if ( test -z "${LINE}" ); then
	break
    fi
    TAG=$(echo "${LINE}" | cut -f 1 -d ":")
    VALUE=$(echo "${LINE}" | cut -f 2- -d " ")
    case $TAG in
    From)   FROM="${VALUE}";;
    Name)   NAME="${VALUE}";;
    Type)   TYPE="${VALUE}";;
    Length) LENGTH="${VALUE}";;
    esac
done

case "${MODE}" in
put)
	if ( test -z "${NAME}" ); then
	    exit 1;
	fi
	
	if ( test -e "${NAME}" ); then
	    exit 1
	fi

        #tell obexpushd to go on
	${DIALOG} --title "Obex-Push" \
            --yesno \
            "Allow receiving the file\n\"${NAME}\"\n(${LENGTH} bytes) from\n${FROM}" \
            10 40
	if ( test "$?" -eq "0" ); then
	    echo "OK"
	else
	    echo "ABORT"
	    exit 1
	fi
	
	cat > "${NAME}"
	;;

get)
	FILE=$(mktemp)
	case "${TYPE}" in
	x-obex/capability)
		obex-capability >${FILE} 2>/dev/null
		;;

	*)
		;;
	esac
	stat --printf="Length: %s\n" ${FILE}
	echo ""
	cat ${FILE}
	rm -f ${FILE}
	;;

esac
exit 0
