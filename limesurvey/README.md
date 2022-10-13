# CVE-2018-7556 LimeSurvey Remote Code Execution

## Description

Unauthenticated Remote Code Execution in LimeSurvey < 3.4.2. The vulnerability is due to an unauthenticated application installation, making it possible for anonymous users to perform reinstallation of the application and passing the exploit code into the config.php file makes it possible to execute the code remotely.

# Deploy

Deploy container in a server public (VPS, Cloud, etc) using docker-compose

```bash
docker-compose up -d
```

# Exploit

```bash
python3 exploit.py
```

> Note: You need to change the IP, URL target in the exploit.py file

# Reference

- https://yeuchimse.com/remote-code-execution-limesurvey-cve-2018-7556/
