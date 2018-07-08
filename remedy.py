import sys
import subprocess
import time
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style

headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
           'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate'}

proxies = {
    'http': 'socks5h://127.0.0.1:9150',
    'https': 'socks5h://127.0.0.1:9150'
}

class utils:

    # Requests module requires that the beginning of a url is either http or https
    # The url_parser() function makes sure that is the case and returns a valid url

    def url_parser(self):

        time.sleep(1)
        self.url = input("[*] Enter a url: ")
        print("\n")


        # Add http:// to beginning of url if not provided --- needed in order to make requests to the site
        # and stores the new url as a valid url that will be used by requests
        if self.url[:7] == "http://" or self.url[:8] == "https://":
            return str(self.url)
        else:
            self.valid_url = "http://" + self.url
            return str(self.valid_url)

    # This function asks the user if a proxy will be used. If yes the function proxy_options() is called to get the proxy info
    # If proxy_options is ran successfully it will return 1 which will make proxy_test() return 1.
    # The return value is used in each main option to set the proxy accordingly on each request.


class XSS_Option:

    def __init__(self, url):
        print(Fore.BLUE + "[+] Crawling " + url + " for input tags.\n")

        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.gcdriver = webdriver.Chrome(chrome_options=self.chrome_options,
                                         executable_path='/home/drax/Downloads/chromedriver')
        self.gcdriver.implicitly_wait(1)  # waits for 8 seconds for everything to load up
        self.gcdriver.get(url)
        self.soup = BeautifulSoup(self.gcdriver.page_source, "html.parser")

        self.xss_parse(url, self.soup)

    # This function parses the returned document from xss_init() and sorts out hidden paramaters from parameters with no name, and regular params.
    def xss_parse(self, url, code):

        d_inputs = []    # displayed inputs EXCLUDING hidden inputs
        hidden_inputs = []  # Just the hidden input fields
        no_name_inputs = 0
        submit_inputs = 0

        # For every input tag that is found the loop will attempt to append the name of the input in the d_inputs list
        # If the input has a name then type is checked to see if it is a hidden input tag or not.
        # If the input tag type is hidden, the name of that input tag will be placed in the hidden field list
        # If the input tag type is anything other than hidden, the name value will be added to the d_inputs list

        # If the input tag does not have a name then the type is then checked to see if it is equal to submit
        # For every submit tag found, the submit_inputs value is increased by one
        # If the input tag type is not equal to submit, the no_name_inputs counter is increased by one
        # If the no name input has no type attribute set then the no_name_inputs is also increased by one

        for input_tag in code.find_all('input'):
            try:
                a = input_tag['name'] # checks to see if the input has a name field
                try:
                    if input_tag['type'] == 'hidden' or input_tag['type'] == 'HIDDEN' or input_tag['type'] == 'Hidden':
                        hidden_inputs.append(input_tag['name'])
                    else:
                        d_inputs.append(input_tag['name'])
                except KeyError as msg:
                    d_inputs.append(input_tag['name'])
            except KeyError as msg:     # this except runs if input tag found has no name
                try:
                    if input_tag['type'] == "Submit" or input_tag['type'] == "submit":
                        submit_inputs += 1  # Submit var gets its value here and is not changed
                    else:
                        no_name_inputs += 1
                except KeyError as msg:
                    no_name_inputs += 1

        # The only difference between test_inputs and total_inputs is total inputs includes the submit inputs as well and not the no_name_inputs
        test_inputs = d_inputs + hidden_inputs  # test_inputs is a array

        total_inputs = len(test_inputs) + no_name_inputs + submit_inputs    # this is a integer

        # This code runs if there are no input tags found at all.

        if total_inputs == 0:
            print("[+] No parameters were found on " + url)
            sys.exit(0)

        # This condition runs if there is only one hidden input tag.

        elif len(d_inputs) == 0 and len(hidden_inputs) >= 1:
            print(Fore.YELLOW + "[+] Found " + str(len(hidden_inputs)) + " hidden inputs.")
            self.xss_test(url, d_inputs)

        # This condition runs if there is 1 or more inputs found without a name.

        elif len(test_inputs) == 0 and len(hidden_inputs) == 0 and no_name_inputs >= 1:
            print("[+] " + str(no_name_inputs) + " inputs found without a name.")
            sys.exit(0)

        elif len(test_inputs) ==0 and len(hidden_inputs) == 0 and no_name_inputs == 0:

        else:
            print("[+] " + str(len(test_inputs)) + " Total Valid Inputs Found: " + str(test_inputs) + "\n")
            print("[+] " + str(len(hidden_inputs)) + " Hidden Inputs Found: " + str(hidden_inputs) + "\n")

            print(Fore.RED + "\t[+] " + str(no_name_inputs) + " Inputs without a name.\n\n")

            self.xss_test(url, d_inputs)

    def xss_test(self, url, vis_inputs):

        self.payload = ['<ScRiPt>document.write("hacked");</ScRiPt>', '<script>document.write("hacked");</script>']

        print(Fore.GREEN + "[+] Testing visible parameters.\n\n")
        for i in vis_inputs:
            self.inputElement = self.gcdriver.find_element_by_name(i)
            self.inputElement.send_keys(self.payload[0])
            self.inputElement.submit()
            if self.payload[1] in self.gcdriver.page_source:
                print(Fore.WHITE + "[+] " + str(i) + " is vulnerable to XSS!\n")
                self.gcdriver.get(url)
                self.gcdriver.implicitly_wait(2)
            else:
                print(Fore.RED + "[*] " + str(i) + " is not vulnerable.\n")
                self.gcdriver.get(url)
                self.gcdriver.implicitly_wait(2)
        self.gcdriver.quit()


def main():
    subprocess.call('clear', shell=True)
    subprocess.call('figlet RemedY', shell=True)    # prints banner if figlet is installed
    print('\tAutomated XSS Scanner')
    print('\t~~ By Daniel Reid ~~')
    print("\n")
    url = utils().url_parser()
    XSS_Option(url)



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as msg:
        sys.exit()
