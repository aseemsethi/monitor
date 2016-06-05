from django.shortcuts import render
from myApp.models import cfg
from django.shortcuts import render, redirect
from myApp.forms import cfgForm
from subprocess import Popen
from django.core import serializers
import json

running = False

# Create your views here.
def index( request): 
	number = 10;
	cfgs = cfg.objects.all()
	return render( request, 'index.html', 
				{'number':number, 'configs': cfgs} )

def cfg_detail(request, slug):
	cfgs = cfg.objects.get(slug=slug)
	return render( request, 'cfg_detail.html', 
				{'configs': cfgs} )

def run_cfg(request, slug):
    # grab the object...
	cfgs = cfg.objects.get(slug=slug)
	print ("Executing Test Case: ")
	'''json_data = serializers.serialize('json',  [cfg.objects.get(slug=slug)])
	print (json_data);'''
	# this gives you a list of dicts
	raw_data = serializers.serialize('python', [cfg.objects.get(slug=slug)])
	# now extract the inner `fields` dicts
	actual_data = [d['fields'] for d in raw_data]
	# and now dump to JSON
	output = json.dumps(actual_data)
	print (output)
	print(cfgs.custID)

	#Open new data file
	configFile = open("/home/asethi/monitor/bin/cc-1", "w")
	configFile.write(output)
	configFile.close()

	cmd_str = "/home/asethi/monitor/monitor/mont_cust " +  str(cfgs.custID) + " " +  cfgs.protocol + " /home/asethi/monitor/bin/cc-1"
	proc = Popen([cmd_str], shell=True,
		stdin=None, stdout=None, stderr=None, close_fds=True)
	return render( request, 'cfg_detail.html', 
				{'configs': cfgs, 'running':True} )

def edit_cfg(request, slug):
    # grab the object...
	cfgs = cfg.objects.get(slug=slug)

	# set the form we're using...
	form_class = cfgForm

	# if we're coming to this view from a submitted form,  
	if request.method == 'POST':
		# grab the data from the submitted form
		form = form_class(data=request.POST, instance=cfgs)
		if form.is_valid():
			# save the new data
			form.save()
			return redirect('cfg_detail', slug=cfgs.slug)

	# otherwise just create the form
	else:
		form = form_class(instance=cfgs)

	# and render the template
	return render(request, 'edit_cfg.html', {
		'thing': cfgs, 'form': form, })
	
