extern void SocksV(char*,int);
typedef void (*SOCK)(char*,int)
#i
int main(){
	
	SocksV("127.0.0.1",1080);
	return 0;
}
