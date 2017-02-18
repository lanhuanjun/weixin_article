import sys, getopt
import weixin_article
opts, args = getopt.getopt(sys.argv[1:], "hi:o:")
input_file=""
output_file=""
name = ''
for op, value in opts:
    if op == "-i":
        input_file = value
    elif op == "-o":
        output_file = value
    elif op == "-n":
        name = value
    elif op == "-h":
        print('-o:输出文件夹')
        print('-i:输出二维码文件路径,以png结尾')
        print('-n:公众号名称')
        print('example:-i c:\\a.png -o c:\\weixin -n CPP开发者')
        sys.exit()

w = weixin_article.weixin(input_file)
w.login()
w.save(name,output_file)
