#!/bin/bash
echo "Getting Sigma Converter Toot"
git clone https://github.com/SigmaHQ/legacy-sigmatools.git
echo "Getting Sigma Rules"
git clone https://github.com/SigmaHQ/sigma.git
echo "Converting sigma rules "

legacy-sigmatools/tools/sigmac --recurse --target sqlite  --backend-option table=Events --output-format json -d sigma/rules/windows/ -c lib/config/sigma-converter-rules-config.yml -o rules.json --output-fields title,id,description,author,tags,level,falsepositives,filename,status


echo "Rules created with file name : rules.json "
