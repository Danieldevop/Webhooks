import hashlib
import hmac
import http.client as http
import json

from django.conf import settings
from django.http import HttpResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt

def handle_webhook(event, payload):
	# Simple webhook handler that prints the event and payload to the console
	print('Received the {} event'.format(event))
	print(json.dumps(payload, indent=4))


@csrf_exempt
def github_view(request):
	github_signature = request.META['HTTP_X_HUB_SIGNATURE']
	signature = hmac.new(bytes(settings.GITHUB_WEBHOOK_SECRET, 'latin-1'), request.body, hashlib.sha1)
	expected_signature = 'sha1=' + signature.hexdigest()
	if not hmac.compare_digest(github_signature, expected_signature):
		return HttpResponseForbidden('Invalid signature Header')

	if 'payload' in request.POST:
		payload = json.loads(request.POST['payload'])

	else:
		payload = json.loads(request.body)

	event = request.META['HTTP_X_GITHUB_EVENT']

	handle_webhook(event, payload)

	return HttpResponse('Webhook received', status=http.ACCEPTED)