import sys
import weixin_article
args = sys.argv
#print(args)
input_file=""
output_file=""
name = ''

x = 2
for op in range(1,len(args),2):
    #print(args[op])
    if args[op] == "-i":
        input_file = args[x]
    elif args[op] == "-o":
        output_file = args[x]
    elif args[op] == "-n":
        name = args[x]
    elif args[op] == "-h":
        print('     -o:输出文件夹')
        print('     -i:输出二维码文件路径,以png结尾')
        print('     -n:公众号名称')
        print('example:-i c:\\a.png -o c:\\weixin -n CPP开发者')
        sys.exit()
    x +=2
if ''==input_file:
    print("error:二维码路径不能为空")
    sys.exit(0)
if ''==output_file:
    print("error:保存路径不能为空")
    sys.exit(0)
if ''==name:
    print("error:微信公众号不能为空")
    sys.exit(0)

w = weixin_article.weixin(input_file)
w.login()
w.save(name,output_file)
