#!/usr/bin/env python
# coding=utf-8


import os
import sys
import time
import redis
import socket
import json
from redis_config import *
from kafka import KafkaProducer
import binascii
from Crypto.Cipher import AES
import base64
#AES_MODE = AES.MODE_CBC
AES_MODE = AES.MODE_ECB
strlist = [0x42,0xd2,0x7a,0x73,0xfc,0x37,0xe2,0x8d,\
    0xd2,0x70,0x5f,0x54,0x41,0x28,0x91,0x77,\
    0x59,0x8f,0x55,0x99,0x93,0x53,0xd7,0x17,\
    0x53,0x35,0x1f,0x03,0x71,0x0d,0xc5,0xd5]

AES_SECRET_KEY = str(bytearray(strlist))

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

reload(sys)
sys.setdefaultencoding('utf-8')


kafka_remote_server = 'kafka'
kafka_local_server = '127.0.0.1'
virus_log_flume_server = 'flume'

KAFKA_CONF = {
    'host': kafka_remote_server,
    'port': 9092,
    'status': 'on'
}

UDP_LOG_CONF = {
    'host': virus_log_flume_server,
    'port': 514,
    'status': 'on'
}

def encrypt( text,key, iv ):
    if AES_MODE == AES.MODE_ECB:
        cryptor = AES.new(key, AES.MODE_ECB)
    else:
        cryptor = AES.new(key, AES_MODE,iv)
    ciphertext = cryptor.encrypt(pad(text))
    return base64.b64encode(ciphertext)

def decrypt( text, key, iv):
    decode = base64.b64decode(text)
    if AES_MODE == AES.MODE_ECB:
        cryptor = AES.new(key, AES.MODE_ECB)
    else:
        cryptor = AES.new(key, AES_MODE,iv)
    plain_text = cryptor.decrypt(decode)
    return plain_text




def redis_log_receicer(host=HOST, port=PORT, db=DB, pw=PW, channel=SUB_CHANNEL, auth=True, max_retry=10, mode='psubscribe'):
    retry = 0
    while 1:
        # try to connect to redis
        try:
            password = pw if auth is True else None
            r = redis.StrictRedis(host=host, port=port, db=db, password=password)
            r.ping()

        except Exception as e:
            # if retry >= max_retry:
            #     break
            # retry += 1
            print e
            time.sleep(1)
            continue

        try:
            ps = r.pubsub()
            if mode == 'psubscribe':
                ps.psubscribe(channel)
            else:
                ps.subscribe(channel)
            
            while 1:
                msg = ps.get_message(ignore_subscribe_messages=True, timeout=1)
                yield msg
        except Exception as e:
            print e
        finally:
            ps.close()
            r.connection_pool.disconnect()


def get_topic_from_channel(chn):
    #two topic return
    if chn == 'netlog_ids':
        return 'ids-topic'
    elif (chn=='netlog_email' or chn=='netlog_ftp' or chn=='netlog_http'):
        return 'virus-topic'
    elif (chn=='netlog_nta_http' or chn=='netlog_nta_netflow'):
        return 'flow-topic'
    else:
        return None

def get_topic_from_channel_to_sendkafka(chn,datain):
    if (chn=='netlog_http'):
        try:
            data = json.loads(datain)
            if data.has_key('Atts') :
                value = "file~%d~%s~%s~%s~%s~%s"%(int(time.time() * 1000000), data['SrcIP'], data['SrcPort'], data['DstIP'], data['DstPort'], data['Atts'][0]['FileName'])
                try:
                    if (data.has_key('Virus') and  float(data['Virus'][0]['virusprobability']) >0.1):
                        udp_forward(host=UDP_LOG_CONF['host'],port=UDP_LOG_CONF['port'],status=UDP_LOG_CONF['status'],msg=datain)
                except Exception as ke:
                    print ke 
                return value
        except Exception as ke:
            print ke
    return None            


def get_topic_from_channel_org(chn):
    if chn == 'netlog_audit_flow':
        return 'netflow-topic'
    if chn == 'netlog_nta_netflow':
        return 'netflow-topic'
    elif chn == 'netlog_ids':
        return 'log-topic'
    elif chn == 'netlog_nta_http':
        return 'http-topic'
    else:
        return 'flow-topic'



def udp_forward(host='127.0.0.1', port=514, status=None,msg=""):
    # print ip, port, proto, status
    if status == 'off' or status == 'OFF':
        return
            # 发送数据:
 #   print "sendmsg" + msg        
    udpsend.sendto(msg.encode('utf-8'), (host, port))
        # 接收数据:

def redis_log_forward(host='127.0.0.1', port=9092, status=None):
    # print ip, port, proto, status
    if status == 'off' or status == 'OFF':
        return

    # new kafka Producer
    kafka_host = host
    kafka_port = port
    kafka_topic = 'flow-topic'

    local_bootstrap_servers=['{kafka_host}:{kafka_port}'.format(kafka_host=kafka_local_server,   kafka_port=port)]
    remote_bootstrap_servers=['{kafka_host}:{kafka_port}'.format(kafka_host=kafka_remote_server,  kafka_port=port)]


    #forward
    producer_remote = KafkaProducer(bootstrap_servers=remote_bootstrap_servers,compression_type='gzip' ,retries=3)
    
    #local
    #producer_local = KafkaProducer(bootstrap_servers=local_bootstrap_servers, retries=3)

    while True:
        try:
            for item in redis_log_receicer(auth=True):
                if item is None:
                    continue
                instr = ' '.join([item['channel'], item['data']])
                kafka_topic = get_topic_from_channel(item['channel'])
                virus_data = get_topic_from_channel_to_sendkafka(item['channel'],item['data'])
                #print kafka_topic
                if kafka_topic is None:
                    continue
                
                try:
                    crypt_str = encrypt(instr, AES_SECRET_KEY, AES_SECRET_KEY[:16])
                    producer_remote.send(kafka_topic, crypt_str)
                    if (virus_data != None):
                        producer_remote.send("sensitive-word-topic", virus_data.encode('utf-8'))
                    #producer_local.send(kafka_topic, instr.encode('utf-8'))
                    #producer_local.send(kafka_topic, instr.encode('utf-8'))
                except Exception as ke:
                    print ke
                    continue
        except Exception as e:
            print e
            continue
    producer.close()


udpsend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

if __name__ == '__main__':
    try:
        # redis_log_receicer(channel='netlog_*')

        redis_log_forward(**KAFKA_CONF)
        udpsend.close()
    except KeyboardInterrupt:
        print 'exit'
