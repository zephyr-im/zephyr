BEGIN {
	foo = 0;
}
/Z.*\(/ { if (foo != 2) foo = 1; }
/{/ { foo = 2; }
{
	if (foo == 1)
	print;
}
