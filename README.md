# **Sensitive Words Detector**
![image](https://github.com/user-attachments/assets/94af96da-2faa-429a-b976-c7be19b640ab)

A **Bash script** designed to automate the process of detecting sensitive words in files or directories, primarily for malware analysis. This tool helps identify potential indicators of compromise by scanning for predefined sensitive words.

---

## **Features**
- Scans for sensitive words in a single file or all files within a directory.
- Outputs results to a report file (`AnalyzedFile.txt`).
- Highlights matches in the terminal using `grep`.
- Detects commonly used sensitive terms in malware analysis, such as:
  - `password`
  - `keylogger`
  - `shellcode`
  - `encryption`
  - `payload`
  - `C2`
  - `trojan`
  - `backdoor`

---

## **Prerequisites**
- A Linux-based operating system with:
  - **Bash shell** (default on most Linux distributions).
  - `grep` command installed (comes pre-installed on most systems).

---

## **Usage**
1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/yourusername/sensitive-words-detector.git
   cd sensitive-words-detector

2. Make the script executable:

```bash
Copy code
chmod +x sensitive_words_detector.sh
```
3. Run the script:
```
bash
./sensitive_words_detector.sh
```
4. Enter the file or directory path when prompted:
- For a file, enter the file path (e.g., example_file.txt).
- For a directory, enter the directory path (e.g., ./malware_samples).

  ## View the results in AnalyzedFile.txt.

