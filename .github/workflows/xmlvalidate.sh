#!/bin/bash
fail=false

# Get all string keys
KEYS=$(grep -oP '<entry[\ ]+lang="[^"]+"[\ ]+key="\K[^"]+' "$1"/src/Common/Language.xml)

for file in {"$1"/Translations/Language.*.xml,"$1"/src/Common/Language.xml}; do
  echo "$file"
  passes=true
  
  # Validate xml
  output=$(fxparser -V "$file")
  returnvalue=$?

  if [ "$returnvalue" -ne "0" ]; then
    passes=false
    fail=true
    echo $output
  fi

  # Ensure each key found in common xml is found in translation xmls
  for key in $KEYS; do
    if ! grep -q "$key" "$file"; then
      echo "Key $key not found in $file"
      passes=false
      fail=true
    fi
  done
  
  if [ "$passes" = true ]; then
    echo -e "\e[32m$file passes xml validation.\e[0m"
  else
    echo -e "\e[31m$file fails xml validation.\e[0m"
  fi
  
done

if [ "$fail" = true ]; then
  exit 1
else
  exit 0
fi
