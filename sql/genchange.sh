#!/bin/bash

dir=`dirname "$0"`
echo $dir
for db in mysql postgres sqlite
do
	for schema in OpenIDConnect
	do
		echo $db : $schema

		php $dir/../../../maintenance/generateSchemaChangeSql.php --json ChangePrimaryKey.json --sql $db/ChangePrimaryKey.sql --type=$db
	done
done
