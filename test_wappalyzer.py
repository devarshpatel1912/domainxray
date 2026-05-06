from Wappalyzer import Wappalyzer, WebPage
import requests

def test_wapp():
    try:
        wappalyzer = Wappalyzer.latest()
        print("Wappalyzer latest loaded.")
        
        url = "https://google.com"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        
        webpage = WebPage.new_from_response(response)
        techs = wappalyzer.analyze_with_categories(webpage)
        
        print(f"Results for {url}:")
        print(techs)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_wapp()
