# confidential-dropbox

This project implements a smarter end to end encryption solution for files hosted on Dropbox. It aims to solve two problems of existing encryption tools availble to Dropbox:

1. When a file is changed we want to only reencrypt the part of the file that is affected by change.
2. When a file is shared between people we want to ensure those people can read and modify the file.
3. Prevent key rot by routinely changing keys and enforcing the use of two or more keys.
