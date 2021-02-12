#!/bin/bash

#Test if stdout is a terminal
if [ -t 1 ]; then
    RED_COLOR=$(echo -en '\e[31m')
    RESET_COLOR=$(echo -en '\033[0m')
else
    RED_COLOR=
    RESET_COLOR=
fi


PF_DIR=/usr/local/pf

DB_PREFIX=pf_smoke_test_

UPGRADED_DB="${DB_PREFIX}_upgraded_$$"

PRISTINE_DB="${DB_PREFIX}_pristine_$$"

HOST=localhost

MYSQL="mysql -upf_smoke_tester -ppacket -h$HOST"

MYSQLDUMP="mysqldump -upf_smoke_tester -h$HOST --no-data -a --skip-comments --routines -ppacket"

CURRENT_SCHEMA="$PF_DIR/db/pf-schema-X.Y.Z.sql"

if [ -e "$CURRENT_SCHEMA" ]; then
    UPGRADE_SCRIPT="$PF_DIR/db/upgrade-X.X.X-X.Y.Z.sql"
    LAST_SCHEMA=$(ls $PF_DIR/db/pf-schema-[0-9]*sql | sort --version-sort -r | head -1)
else
    CURRENT_SCHEMA="$PF_DIR/db/pf-schema.sql"
    if [ ! -f "$CURRENT_SCHEMA" ]; then
        CURRENT_SCHEMA=$(ls $PF_DIR/db/pf-schema-[0-9]*sql | sort --version-sort -r | head -1 )
    fi
    LAST_SCHEMA=$(ls $PF_DIR/db/pf-schema-[0-9]*sql | sort --version-sort -r | head -2 | tail -1)
    UPGRADE_SCRIPT=$(ls $PF_DIR/db/upgrade-[0-9]*sql | sort --version-sort -r | head -1)
fi

for db in $UPGRADED_DB $PRISTINE_DB;do
    $MYSQL -e"DROP DATABASE IF EXISTS $db;"
    if [ $? != "0" ];then
        echo "Error dropping database $db"
        exit 1;
    fi
    $MYSQL -e"CREATE DATABASE $db;"
    if [ $? != "0" ];then
        echo "Error creating database $db"
        exit 1;
    fi
    echo "Created test db $db"
done


echo "Applying last schema $LAST_SCHEMA"

$MYSQL $UPGRADED_DB < "$LAST_SCHEMA"

echo "Applying upgrade script $UPGRADE_SCRIPT"

$MYSQL $UPGRADED_DB < "$UPGRADE_SCRIPT"
if [ $? != "0" ];then
    echo "Error applying upgrade script $UPGRADE_SCRIPT"
    exit 1;
fi

echo "Applying current schema $CURRENT_SCHEMA"

$MYSQL $PRISTINE_DB < "$CURRENT_SCHEMA"
if [ $? != "0" ];then
    echo "Error applying current schema $CURRENT_SCHEMA"
    exit 1;
fi

for db in $UPGRADED_DB $PRISTINE_DB;do
    $MYSQLDUMP $db > "${db}.dump"
done

#Ignore sort of indexes but ensure sort order of columns
if [ -n "$(diff -w <(sort "${PRISTINE_DB}.dump" | perl -pi -e's/,$//')  <(sort "${UPGRADED_DB}.dump" | perl -pi -e's/,$//'))" ] ||
    [ -n "$(diff -w <(perl -pi -e's/^\s*(KEY|CONSTRAINT).*$//' < "${PRISTINE_DB}.dump")   <(perl -pi -e's/^\s*(KEY|CONSTRAINT).*$//' <  "${UPGRADED_DB}.dump"))" ];then
    diff -uw "${PRISTINE_DB}.dump" "${UPGRADED_DB}.dump" > "${UPGRADED_DB}.diff"
    echo "${RED_COLOR}Upgrade did not create the same db"
    echo "Please look at ${UPGRADED_DB}.diff for the differences"
    echo "You can also look at ${PRISTINE_DB}.dump and ${UPGRADED_DB}.dump${RESET_COLOR}"
    exit 1
else
    echo "Upgrade is successful"
    rm -f "${PRISTINE_DB}".dump "${UPGRADED_DB}".dump
fi

for db in $UPGRADED_DB $PRISTINE_DB;do
    echo "Deleting test db $db"
    $MYSQL -e"DROP DATABASE IF EXISTS $db;"
done
