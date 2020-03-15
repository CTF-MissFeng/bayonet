ps -ef |grep python |awk '{print $2}'|xargs kill -9
ps -ef |grep xray |awk '{print $2}'|xargs kill -9