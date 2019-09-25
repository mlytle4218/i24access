#!/usr/bin/env python3
import i24newsStreamer as ns
import subprocess
import os
import math
import time
from datetime import datetime
import re
import click

width = int( subprocess.check_output(['tput','cols']) )
height = int( subprocess.check_output(['tput','lines']) ) -1

def convert(duration):
    duration = int(duration)
    seconds=(duration/1000)%60
    seconds = int(seconds)
    minutes=(duration/(1000*60))%60
    minutes = int(minutes)
    hours=(duration/(1000*60*60))%24
    hours = int(hours)

    return hours,minutes,seconds



def beep():
    print('\a')

def print_out_menu_options(options):
    choices = set()
    full = math.floor(len(options) / height )
    remainder = len(options) - (full * height)


    display_control = []
    counter = 0
    for each in range(full):
        temp = []
        for itr in range(height):
            temp.append(counter)
            counter+=1

        display_control.append(temp)
    temp = []
    for each in range(remainder):
        temp.append(counter)
        counter+=1

    display_control.append(temp)

    page_itr = 0

    while True:
        os.system('clear')
        for each in display_control[page_itr]:
            hours,minutes,seconds = convert(options[each]['duration'])
            if hours > 0:
                print('number {} {} - {}:{}:{}'.format(each + 1, options[each]['title'], hours, minutes, seconds ))
            else:
                print('number {} {} - {}:{}'.format(each + 1, options[each]['title'], minutes, seconds ))

        result = input('choice ')
        result_list = result.split(' ')
        if len(result_list) > 1:
            for item in result_list:
                try:
                    item = int(item)
                    choices.add(item - 1)
                except ValueError:
                    pass
        else:
            try:
                result = int(result)
                choices.add(result - 1)
            except ValueError:
                if result == 'n':
                    if page_itr < len(display_control) -1:
                        page_itr +=1
                    else:
                        beep()
                elif result =='p':
                    if page_itr > 0:
                        page_itr -=1
                    else:
                        beep()
                elif result =='q':
                    for choice in choices:
                        assetId = options[choice]['assetId']
                        descriptor = streamer.get_brightcove_new(assetId)
                        streams = []
                        for item in descriptor['sources']:
                            if 'ext_x_version' in item:
                                streams.append(item['src'])
                        title_start = options[choice]['title'].split('|')
                        title = ''
                        date = ''
                        if len(title_start) == 2:
                            title = title_start[0].strip().lower()
                            title = re.sub(r'[^\w\s]','',title)
                            title = re.sub(" ","-",title)
                            date = title_start[1].split(',')[1].strip()

                        elif len(title_start) == 3:
                            title = title_start[1].strip().lower()
                            title = re.sub(r'[^\w\s]','',title)
                            title = re.sub(" ","-",title)
                            date = title_start[2].split(',')[1].strip()

                        date_array = date.split()
                        month = int(datetime.strptime(date_array[0], '%B').month)
                        date = int(re.sub("[^0-9]", "", date_array[1]))
                        year = date_array[2]
                        date_string = "{}-{:02d}{:02d}{}".format(title,month,date,year)




                        cwd = os.getcwd()
                        file_location = cwd + "/" +date_string + ".mp4"
                        if len(streams) > 0:
                            print("Saving {}".format(file_location))
                            command = ['ffmpeg','-y','-loglevel','error','-i',streams[0],"-vn","-c:a","copy",file_location]
                            subprocess.run(command)
                            print('{} is done saving'.format(date_string))


                    break
                else:
                    beep()


ns.record_live = False
ns.record_option = False
temp_options = [
    ['live',beep],
    ['news',beep]
]


requests_session = ns.HTMLSession()
streamer = ns.NewsStreamer(requests_session, '/home/chime/virtual-python/credentials.json')
streamer.auth()


@click.command()
@click.option('--live','-l', is_flag=True, help='Listen to the live stream only')
@click.option('--record','-r', help='Record the live stream only - must provide a file and location')
def main_menu(live, record):
    url = 'https://video.i24news.tv/proxy/page/live?appId=5a8452d11de1c4000c77c692&uuid={}'.format(streamer.uuid)
    ops = streamer.get_selected(url)
    descriptor = streamer.get_brightcove_new(ops[0]['assetId'])
    src = descriptor['sources'][0]['src']
    if record:
        print("Saving {}".format(record))
        command = ['ffmpeg','-y','-loglevel','error','-i',src,"-vn","-c:a","copy",record]
        subprocess.run(command)
        print('{} is done saving'.format(record))
    elif live:
        print("Playing {}".format(src))
        sound_cards = {
            0:"--audio-device=alsa/plughw:CARD=Intel,DEV=0",
            1:"--audio-device=alsa/plughw:CARD=AudioPCI,DEV=0",
            2:"--audio-device=alsa/plughw:CARD=DGX,DEV=0",
            3:"--audio-device=alsa/plughw:CARD=Audigy2,DEV=0"
        }
        os.system('clear')
        for each,i in enumerate(sound_cards):
            print("number {} for mpv{}".format(i+1, i))
        result = input('choice ')
        try:
            result = int( result)
            command = ['mpv', "--really-quiet","--no-video",sound_cards[result], src]
            subprocess.run(command)
        except ValueError:
            pass

    else:
        while True:
            os.system('clear')
            print('number 1 live')
            print('number 2 news')
            print('number 3 tv shows')
            result = input('choice ')
            try:
                result = int( result )
                if result == 1:
                    url = 'https://video.i24news.tv/proxy/page/live?appId=5a8452d11de1c4000c77c692&uuid={}'.format(streamer.uuid)
                    ops = streamer.get_selected(url)
                    print_out_menu_options(ops)
                elif result == 2:
                    url = 'https://video.i24news.tv/proxy/page/news?appId=5a8452d11de1c4000c77c692&uuid={}'.format(streamer.uuid)
                    ops = streamer.get_selected(url)
                    print_out_menu_options(ops)
                elif result == 3:
                    url = 'https://video.i24news.tv/proxy/page/tv-shows?appId=5a8452d11de1c4000c77c692&uuid={}'.format(streamer.uuid)
                    ops = streamer.get_selected(url)
                    print_out_menu_options(ops)
            except ValueError:
                if result == 'q':
                    break

main_menu()

# print( vars( streamer ) )
# streamer.show_menu()
