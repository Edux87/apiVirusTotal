import falcon
import requests
import json

class defaultResource:
    def on_get(self, req, resp):
        resp.data = json.dumps({'message': 'Api Virus Total Ready!'})
        resp.content_type = 'application/json'
        resp.status = falcon.HTTP_200

class vtSendResource:
    def on_post(self, req, resp):
         try:
             raw_json = req.stream.read()
         except Exception as ex:
             raise falcon.HTTPError(falcon.HTTP_400,'Error',ex.message)

         try:
            result = json.loads(raw_json, encoding='utf-8')

            url = "https://www.virustotal.com/vtapi/v2/url/scan"
            analise = result['url']
            payload = "-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"url\"\r\n\r\n" + analise + "\r\n-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"apikey\"\r\n\r\n2ab17da03f5f5268238aedbf2da10f850b28d7f1d5dd100b404a9ae4c10d069e\r\n-----011000010111000001101001--"
            headers = {
                'content-type': "multipart/form-data; boundary=---011000010111000001101001",
                'cache-control': "no-cache"
                }
            r = requests.request("POST", url, data=payload, headers=headers)
            resp.body = (r.text)

         except ValueError:
            raise falcon.HTTPError(falcon.HTTP_400,'Invalid JSON','Could not decode the request body. The JSON was incorrect.')

class vtReportResource:
    def on_post(self, req, resp):
         try:
             raw_json = req.stream.read()
         except Exception as ex:
             raise falcon.HTTPError(falcon.HTTP_400,'Error',ex.message)

         try:
            result = json.loads(raw_json, encoding='utf-8')

            url = "https://www.virustotal.com/vtapi/v2/url/report"
            analise = result['url']
            payload = "-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"resource\"\r\n\r\n" + analise + "\r\n-----011000010111000001101001\r\nContent-Disposition: form-data; name=\"apikey\"\r\n\r\n2ab17da03f5f5268238aedbf2da10f850b28d7f1d5dd100b404a9ae4c10d069e\r\n-----011000010111000001101001--"
            headers = {
                'content-type': "multipart/form-data; boundary=---011000010111000001101001",
                'cache-control': "no-cache"
                }
            r = requests.request("POST", url, data=payload, headers=headers)
            resp.body = (r.text)
         except ValueError:
            raise falcon.HTTPError(falcon.HTTP_400,'Invalid JSON','Could not decode the request body. The JSON was incorrect.')


api = falcon.API()

vtSend = vtSendResource()
vtReport = vtReportResource()
df = defaultResource()

api.add_route('/', df)
api.add_route('/analise', vtSend)
api.add_route('/report', vtReport)