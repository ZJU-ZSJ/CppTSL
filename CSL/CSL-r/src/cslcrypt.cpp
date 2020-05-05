/*
** Shijie Zhang, 2019
*/

////////////////////////////////////////////////////////////////////////////////

#include "precomp.h"

////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
namespace CSL {
////////////////////////////////////////////////////////////////////////////////

void Cslcrypt::mainLoop(unsigned int M[])
{
    unsigned int f, g;
    unsigned int a = atemp;
    unsigned int b = btemp;
    unsigned int c = ctemp;
    unsigned int d = dtemp;
    for (unsigned int i = 0; i < 64; i++)
    {
        if (i < 16)
        {
            f = F(b, c, d);
            g = i;
        }
        else if (i < 32)
        {
            f = G(b, c, d);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48)
        {
            f = H(b, c, d);
            g = (3 * i + 5) % 16;
        }
        else
        {
            f = I(b, c, d);
            g = (7 * i) % 16;
        }
        unsigned int tmp = d;
        d = c;
        c = b;
        b = b + shift((a + f + k[i] + M[g]), s[i]);
        a = tmp;
    }
    atemp = a + atemp;
    btemp = b + btemp;
    ctemp = c + ctemp;
    dtemp = d + dtemp;
}

////////////////////////////////////////////////////////////////////////////////

/*
*填充函数
*/
unsigned int *Cslcrypt::add(string str)
{
    unsigned int num = ((str.length() + 8) / 64) + 1;
    auto *strByte = new unsigned int[num * 16];
    strlength = num * 16;
    for (unsigned int i = 0; i < num * 16; i++)
        strByte[i] = 0;
    for (unsigned int i = 0; i < str.length(); i++)
    {
        strByte[i >> 2] |= (str[i]) << ((i % 4) * 8);
    }
    strByte[str.length() >> 2] |= 0x80 << (((str.length() % 4)) * 8);
    strByte[num * 16 - 2] = str.length() * 8;
    return strByte;
}

////////////////////////////////////////////////////////////////////////////////

string Cslcrypt::changeHex(int a)
{
    int b;
    string str1;
    string str = "";
    for (int i = 0; i < 4; i++)
    {
        str1 = "";
        b = ((a >> i * 8) % (1 << 8)) & 0xff; //逆序处理每个字节
        for (int j = 0; j < 2; j++)
        {
            str1.insert(0, 1, str16[b % 16]);
            b = b / 16;
        }
        str += str1;
    }
    return str;
}

////////////////////////////////////////////////////////////////////////////////

string Cslcrypt::md5_get(string str)
{
    atemp = A;
    btemp = B;
    ctemp = C;
    dtemp = D;
    unsigned int *strByte = add(str);
    for (unsigned int i = 0; i < strlength / 16; i++)
    {
        unsigned int num[16];
        for (unsigned int j = 0; j < 16; j++)
            num[j] = strByte[i * 16 + j];
        mainLoop(num);
    }
    return changeHex(atemp).append(changeHex(btemp)).append(changeHex(ctemp)).append(changeHex(dtemp));
}

////////////////////////////////////////////////////////////////////////////////

string Cslcrypt::md5_salt_get(const string& str)
{
    string salt = salt_generate();
    string md5_tmp = salt_insert(md5_get(str + salt), salt);
    return md5_tmp;
}

////////////////////////////////////////////////////////////////////////////////

string Cslcrypt::salt_generate()
{
    string res;
    srand(time(nullptr));
    int i;
    for (i = 0; i < 16; ++i)
    {
        switch ((rand() % 3))
        {
            case 1:
                res += 'A' + rand() % 26;
                break;
            case 2:
                res += 'a' + rand() % 26;
                break;
            default:
                res += '0' + rand() % 10;
                break;
        }
    }
    return res;
}

////////////////////////////////////////////////////////////////////////////////

string Cslcrypt::salt_insert(const string& source, const string& salt)
{
    return source + salt; //这里直接将salt接在密文后面，也可以用其他规定的方式存起来
}

////////////////////////////////////////////////////////////////////////////////
}
////////////////////////////////////////////////////////////////////////////////