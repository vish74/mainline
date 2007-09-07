#!/bin/sh

#DIALOG=Xdialog --default-no
DIALOG=kdialog

#
# compatible with obexpushd 0.6
#

#only put is supported
if ( test "$1" = "get" ); then
    exit 1
fi

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
exit 0
