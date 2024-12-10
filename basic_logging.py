import os,pathlib,datetime


class Logger:
    def __init__(self,*,name: str = "logs",format: str = "{date} {time} {msg}") -> None:
        self._name = name
        self._format = format
        if not pathlib.Path("logs").is_dir():
            os.mkdir("logs")
        
        date = ".".join(reversed(str(datetime.datetime.now().date()).replace("-",".").split(".")))
        time = str(datetime.datetime.now().time()).split(".")[0]
        self._fn = "logs/{date}-{time}-{name}.log".format(date=date,time=time,name=self._name)
        with open(self._fn,"w+b") as file:
            file.write("".encode())
    def info(self,msg):
        date = ".".join(reversed(str(datetime.datetime.now().date()).replace("-",".").split(".")))
        time = str(datetime.datetime.now().time()).split(".")[0]
        with open(self._fn,"w+b") as file:
            file.write(self._format.format(date=date,time=time,msg=msg).encode())
    def warning(self,msg):
        date = ".".join(reversed(str(datetime.datetime.now().date()).replace("-",".").split(".")))
        time = str(datetime.datetime.now().time()).split(".")[0]
        with open(self._fn,"w+b") as file:
            file.write(("[WARNING] "+self._format.format(date=date,time=time,msg=msg)).encode())