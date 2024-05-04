#POST http://localhost:8080/csrf/client/public
#
#HTTP/1.1 200
#Content-Type: text/plain;charset=UTF-8
#Content-Length: 175
#Date: Sat, 04 May 2024 09:54:55 GMT
#
#{"body":{"data":{"token":"7939c340e479fa01f7ece2d3ae0388b76eb88ca18360a36ad9e40cf03a5f75d6326a4e2bb358c36cc90984bdbdf200c4db4300d31f31ef0ad2d60e5c87e62356"}},"statusCode":200}
#


# sequential compared to version 3.0.0

#Response code: 200; Time: 2377ms (2 s 377 ms); Content length: 175 bytes (175 B)
#Response code: 200; Time: 1119ms (1 s 119 ms); Content length: 175 bytes (175 B)
#Response code: 200; Time: 1155ms (1 s 155 ms); Content length: 175 bytes (175 B)
#Response code: 200; Time: 1102ms (1 s 102 ms); Content length: 175 bytes (175 B)



# parallel in version 3.1.0

#Response code: 200; Time: 3301ms (3 s 301 ms); Content length: 175 bytes (175 B)
#Response code: 200; Time: 2822ms (2 s 822 ms); Content length: 175 bytes (175 B)
#Response code: 200; Time: 2794ms (2 s 794 ms); Content length: 175 bytes (175 B)
#Response code: 200; Time: 2852ms (2 s 852 ms); Content length: 175 bytes (175 B)