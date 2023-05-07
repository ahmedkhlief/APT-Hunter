#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Please enter rules path as argument "
  exit 1
fi

echo "Getting Sigma Converter Toot"
git clone https://github.com/SigmaHQ/legacy-sigmatools.git
echo "Converting sigma rules "

legacy-sigmatools/tools/sigmac --recurse --target sqlite  --backend-option table=Events --output-format json -d $1 -c lib/config/sigma-converter-rules-config.yml -o rules.json --output-fields title,id,description,author,tags,level,falsepositives,filename,status


echo "Rules created with file name : rules.json "
