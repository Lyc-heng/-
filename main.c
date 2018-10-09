#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

int globa = 5;
char globa1 = 'c';

void __stdcall test(int value) {
	int a = value;
	value = globa;
	char b = globa1;
	if (a < 0)
	{
		a = 0;
	}
	else
	{
		a = -1;
	}
	MessageBox(NULL, TEXT("FirstFunction"), TEXT("title"), MB_OK);
}

int _cdecl sum(int a, int b) {
	char c = 'a';
	test(a);
	MessageBox(NULL, TEXT("SecondFunction"), TEXT("title"), MB_OK);
	return a;
}

int _cdecl RandomTwoNumber(int a, int b) {
	return rand() - a + rand() - b;
}
int main() {
	int number_a = 1;
	unsigned int number_b = 2;
	unsigned char d = 'b';
	void *p = (void*)0x52345678;
	number_b = sum(number_a, number_b);
	number_b = RandomTwoNumber(number_a, number_b);
	if (number_b == 5) {
		MessageBox(NULL, TEXT("b = 5"), TEXT("title"), MB_OK);
		if (number_b == 5) {
			MessageBox(NULL, TEXT("b = 5"), TEXT("title"), MB_OK);
		}
	}
	else {
		if (number_a >= 0)
		{
			number_a = 0;
		}
		else
		{
			number_a = 5;
		}
	}
	char temp = 'd';
	for (int i = 0; i < 5; i++) {
		i = i;
	}
	char temp1 = 'a';
	switch (number_a)
	{
	case  3:
		MessageBox(NULL, TEXT("a = 4"), TEXT("title"), MB_OK);
		break;
	case 4:
		MessageBox(NULL, TEXT("a = 5"), TEXT("title"), MB_OK);
		break;
	case 5:
		MessageBox(NULL, TEXT("a = 5"), TEXT("title"), MB_OK);
		break;
	case 6:
		MessageBox(NULL, TEXT("a = 5"), TEXT("title"), MB_OK);
		break;
	case 7:
		MessageBox(NULL, TEXT("a = 5"), TEXT("title"), MB_OK);
		break;
	default:
		break;
	}

	ExitProcess(0);
}