#!/bin/sh

ACCEPTED=test.alerting.example.org
REJECTED=test.alerting.example.net
PORT=5300
HOST=localhost
DIG_OPTS="-p $PORT +notcp +nocmd +qr +nocomment +tries=1 +timeout=1 @$HOST"
NS_OPTS="-port=$PORT -retry=0 -timeout=1"
NC="nc -u -w1 $HOST $PORT"
XXD="xxd -r -p"

expect() {
	if [ $1 != $2 ]
	then
		echo "unexpected return value $1 vs $2"
		exit 1
	fi
}

expect_not_empty() {
	test -z "$1"
	expect $? 1
}

expect_empty() {
	test -z "$1"
	expect $? 0
}

echo "test bogus data rejection with netcat"
REPLY=$(echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | $NC)
expect_empty "$REPLY"

echo "test accepted domain with netcat"
REPLY=$(echo '
		6162012000010000000000000372617708616c657274696e67076578616d706c65036f
		72670000010001
	' | $XXD | $NC)
expect_not_empty "$REPLY"

echo "test two question query of rejected/accepted"
REPLY=$(echo '
		6162012000020000000000000372617708616c657274696e67076578616d706c65036f
		726700000100020372617708616c657274696e67076578616d706c65036f7267000001
		0001
	' | $XXD | $NC)
expect_not_empty "$REPLY"

echo "test two question query of rejected/accepted with pointer name"
REPLY=$(echo '
		6162012000020000000000000372617708616c657274696e67076578616d706c65036f
		72670000010002c00c00010001
	' | $XXD | $NC)
expect_not_empty "$REPLY"

echo "test forward pointer rejection"
REPLY=$(echo '
		6162012000010000000000000372617708616c657274696e67076578616d706c65036f
		7267c02900010001
	' | $XXD | $NC)
expect_empty "$REPLY"

echo "test pointer loop rejection"
REPLY=$(echo '
		6162012000010000000000000372617708616c657274696e67076578616d706c65036f
		7267c00c00010001
	' | $XXD | $NC)
expect_empty "$REPLY"

echo "test long label acceptance"
REPLY=$(echo '
		6162012000010000000000003f61616161616161616161616161616161616161616161
		6161616161616161616161616161616161616161616161616161616161616161616161
		61616161616108616c657274696e67076578616d706c65036f72670000010001
	' | $XXD | $NC)
expect_not_empty "$REPLY"

echo "test long label rejection"
REPLY=$(echo '
		6162012000010000000000004061616161616161616161616161616161616161616161
		6161616161616161616161616161616161616161616161616161616161616161616161
		6161616161616108616c657274696e67076578616d706c65036f72670000010001
	' | $XXD | $NC)
expect_empty "$REPLY"

echo "test long name rejection"
REPLY=$(echo '
		6162012000010000000000003f61616161616161616161616161616161616161616161
		6161616161616161616161616161616161616161616161616161616161616161616161
		6161616161613f61616161616161616161616161616161616161616161616161616161
		6161616161616161616161616161616161616161616161616161616161616161616161
		3f61616161616161616161616161616161616161616161616161616161616161616161
		61616161616161616161616161616161616161616161616161616161613f6161616161
		6161616161616161616161616161616161616161616161616161616161616161616161
		616161616161616161616161616161616161616161616108616c657274696e67076578
		616d706c65036f72670000010001
	' | $XXD | $NC)
expect_empty "$REPLY"

echo "test invalid character rejection"
REPLY=$(echo '
		61620120000100000000000003722e7708616c657274696e67076578616d706c65036f
		72670000010001
	' | $XXD | $NC)
expect_empty "$REPLY"

echo "test invalid digit start label rejection"
REPLY=$(echo '
		6162012000010000000000000330617708616c657274696e67076578616d706c65036f
		72670000010001
	' | $XXD | $NC)
expect_empty "$REPLY"

echo "test invalid hyphen end label rejection"
REPLY=$(echo '
		6162012000010000000000000372612d08616c657274696e67076578616d706c65036f
		72670000010001
	' | $XXD | $NC)
expect_empty "$REPLY"

echo "test accepted domain with dig"
dig $DIG_OPTS $ACCEPTED
expect $? 0

echo "test rejected domain with dig"
dig $DIG_OPTS $REJECTED
expect $? 9

echo "test rejected empty with dig"
dig $DIG_OPTS +header-only
expect $? 9

echo "test rejected CHAOS class with dig"
dig $DIG_OPTS -c CH $ACCEPTED
expect $? 9

echo "test rejected IQUERY with dig"
dig $DIG_OPTS +opcode=1 $ACCEPTED
expect $? 9

echo "test rejected reverse lookup with dig"
dig $DIG_OPTS -x 127.0.0.1
expect $? 9

echo "test accepted domain with nslookup"
nslookup $NS_OPTS $ACCEPTED $HOST
expect $? 1

echo "test rejected domain with nslookup"
nslookup $NS_OPTS $REJECTED $HOST
expect $? 1

echo "passed"
