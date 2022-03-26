#!/bin/bash

dir=`dirname "$0"`
echo $dir
for db in mysql postgres sqlite
do
	for schema in OpenIDConnect
	do
		echo $db : $schema

		php $dir/../../../maintenance/generateSchemaSql.php --json $schema.json --sql $db/$schema.sql --type=$db
	done
done
