import cgi
import json
import argparse
import requests
import base64
from datetime import datetime
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer

class GetHandler(BaseHTTPRequestHandler):
    def forward_to_SOAP_service(self, json_data, image):
        url= cli_args.soap_service_url
        soap_action = "http://tempuri.org/PostImage"
        service_user = cli_args.user
        service_key = cli_args.service_key

        soap_template = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
            <soapenv:Header/>
            <soapenv:Body>
                <tem:PostImage>
                <tem:user>{}</tem:user>
                <tem:password>{}</tem:password>
                <tem:date>{}</tem:date>
                <tem:plate>{}</tem:plate>
                <tem:score>{}</tem:score>
                <tem:image>{}</tem:image>
                </tem:PostImage>
            </soapenv:Body>
        </soapenv:Envelope>
        """

        timestamp = json_data['data']['timestamp_local']
        plate = json_data['data']['results'][0]['plate']
        score = json_data['data']['results'][0]['score']

        # Format timestamp and filename
        parsed_timestamp = datetime.strptime(timestamp[:26], "%Y-%m-%d %H:%M:%S.%f")
        
        formatted_timestamp = parsed_timestamp.strftime("%-m/%-d/%Y %H:%M:%S")

        # Format SOAP XML content
        soap_xml = soap_template.format(service_user, service_key,formatted_timestamp, plate, score, image)

        print(soap_xml)

        # Headers for the POST request
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{soap_action}"'}

        response = requests.post(url, data=soap_xml,headers=headers)


        if response.status_code == 200:
            #self.wfile.write(b"SOAP request successful.")
            #self.wfile.write(b"Response content: " + response.content)
            print("SOAP request successful.")
            print("Response content: " + str(response.content))

        else:
            #self.wfile.write("SOAP request failed. Status code: {}".format(response.status_code).encode())
            #self.wfile.write(b"Response content: " + response.content)
            print("SOAP request failed. Status code: {}".format(response.status_code))
            print("Response content: " + str(response.text))

        return response

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Send a POST request instead.")
        return

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        ctype, pdict = cgi.parse_header(self.headers["Content-Type"])
        image_base64 = None
        if ctype == "multipart/form-data":
            pdict["boundary"] = bytes(pdict["boundary"], "utf-8")
            fields = cgi.parse_multipart(self.rfile, pdict)
            # Get webhook content           
            json_data = json.loads(fields.get("json")[0])
            try:
                buffer = fields.get("upload")[0]
                image_base64 = base64.b64encode(buffer).decode('utf-8')
            except:
                print("not file")
        else:
            raw_data = self.rfile.read(int(self.headers["content-length"])).decode(
                "utf-8"
            )

            # Parse the form data into a dictionary
            parsed_data = parse_qs(raw_data)

            # Convert the dictionary to JSON format
            dumps_data = json.dumps(parsed_data)

            parsed_data = json.loads(dumps_data)

            # Extract the nested JSON string from the list
            json_string = parsed_data['json'][0]

            # Parse the nested JSON string
            json_data = json.loads(json_string)

        self.forward_to_SOAP_service(json_data, image_base64)
        self.wfile.write(b"OK")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Receive webhook POST function and forward it to a SOAP service",
        epilog="",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.epilog += (
        "Examples:\n"
        "Send webhooks POST function type to a SOAP service: "
        "./webhook_to_soap_middleware.py --soap-service-url <YOUR_SERVICE_URL> --user <USER_NAME> --service-key <SERVICE_KEY>"
    )

    parser.add_argument(
        "-s",
        "--soap-service-url",
        help="Url of the SOAP service",
        required=False,
    )

    parser.add_argument(
        "-u",
        "--user",
        help="User name field for SOAP service authentication",
        required=False,
    )

    parser.add_argument(
        "-k",
        "--service-key",
        help="Key field for SOAP service authentication",
        required=False,
    )

    cli_args = parser.parse_args()

    if not cli_args.soap_service_url:
        raise Exception("Url of the SOAP service is required")

    #use IP address, not localhost, not 127.0.0.1, etc
    server = HTTPServer(("", 8002), GetHandler)
    print("Starting server, use <Ctrl-C> to stop")
    server.serve_forever()
