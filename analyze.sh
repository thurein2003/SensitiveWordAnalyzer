#!/bin/bash

SENSITIVE_WORDS=("password" "keylogger" "shellcode" "encryption" "payload" "C2" "trojan" "backdoor")

read -p "Enter the file name : " INPUT_PATH

if [ ! -e "$INPUT_PATH" ]; then
	echo "Error : $INPUT_PATH does not exist..."
	exit 1
fi

OUTPUT_FILE="AnalyzedFile.txt"
> "$OUTPUT_FILE"

#to scan a file 
scanFile() {
	local file=$1
	echo "Scanning $file"

	for words in "${SENSITIVE_WORDS[@]}"; do 
		matches=$(grep -i --color=always "$words" "$file")

		if [ ! -z "$matches" ]; then
			echo "Sentative words '$words' was found in the file > $file" | tee -a "OUTPUT_FILE"
			echo "$matches" >> "$OUTPUT_FILE"
		fi
	done
}

#Check the input
if [ -f "$INPUT_PATH" ]; then
	scanFile "$INPUT_PATH"
elif [ -d "$INPUT_PATH" ]; then
	echo "Scanning the directory > $INPUT_PATH..."

		for file in "$INPUT_PATH"/*; do 
			if [ -f "$file" ]; then
				scanFile "$file"
			fi
		done
else 
	echo " Your input $INPUT_PATH is neither file nor directory"
	exit 1
fi 

echo "Scanning script is finished and saved in $OUTPUT_FILE..."