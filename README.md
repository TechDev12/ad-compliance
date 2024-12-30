This script will generate a HTML report that will check your AD for benchmark controls for CIS, NIST, SOX, GDPR & HIPAA, As well for AD user enumeration with user expiry and complex password policy enablement. 

For all the metrics to work properly ensure the script is executed with Administrative privileges

**Usage example:
.\ad-compilance.ps1 -dchostname "your domain controller hostname" -domain "yourdomain.com" -signature "signature inside the html report"**

You can modify the script to include your own logo to be added into the report.
