const express = require('express');
const path = require('path');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const cors = require('cors');
const index = require('./routes/index');
const users = require('./routes/users');
const rp = require('request-promise');
const bignum = require("bignum");
const readline = require('readline');
const crypto = require('crypto');
const app = express();
app.use(cors());
// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/', index);
app.use('/users', users);
// catch 404 and forward to error handler
app.use(function (req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});
// error handler
app.use(function (err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    res.send('error');
});
/*
 *
 * DiffieHellman Client
 *
 */
//RFC 3526  MODP Diffie-Hellman groups for IKE May 2003 The generator is: 2.
const p = bignum('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA' +
    '63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B5766' +
    '25E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE' +
    '45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F35620855' +
    '2BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E860' +
    '39B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA05101' +
    '5728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB39' +
    '70F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8760' +
    '2733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BF' +
    'CE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B' +
    '6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA09' +
    '0C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FD' +
    'DC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37B' +
    'DF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED4' +
    '4CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF03' +
    '2EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97' +
    'A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715E' +
    'EF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76' +
    'E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A93' +
    '2DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F' +
    '5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C' +
    '73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66' +
    'D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D' +
    '510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190' +
    'DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFF' +
    'FFFFFFFFF', base = 16);
const g = bignum(2);    // Recommended g for prime g RFC 3526
const four = bignum(4); // Init range value to 4
const a = four.rand(p); // Rand between 4 and p mod p
const ga = g.powm(a, p); // g pow a mod p
let isFirstMessage = true;
let exit = false;
const pgParams = {
    method: 'POST',
    uri: 'http://localhost:3001/api/bob/pg',
    body: {
        p: p.toString(),
        g: g.toString()
    },
    json: true // Automatically stringifies the body to JSON
};
const gaParams = {
    method: 'POST',
    uri: 'http://localhost:3001/api/bob/ga',
    body: {
        ga: ga.toString()
    },
    json: true // Automatically stringifies the body to JSON
};

let send = async function sendEncryptedMessage(msg) { //Using request-promise library
    let kabh;
    try {
        if (isFirstMessage) { //Future Impl.
            kabh = await generateHashedKey();
            isFirstMessage = false;
        }
        let encryptedMessage = encryptMessage(kabh, msg);
        const msgParams = {
            method: 'POST',
            uri: 'http://localhost:3001/api/bob/msg',
            body: {
                iv: encryptedMessage.iv.toString(16),
                encryptedMessage: encryptedMessage.encrypted.toString(16)
            },
            json: true // Automatically stringifies the body to JSON
        };
        let ack = await rp(msgParams);
        console.log(ack);
    } catch (e) {
        console.log(e);
    }
};

async function generateHashedKey() {
    try {
        rp(pgParams);
        let gb = bignum((await rp(gaParams)).gb);
        let kab = bignum(gb).powm(a, p);
        return crypto.createHash('sha256').update(kab.toString(16), 'hex').digest('hex');
    } catch (e) {
        console.log(e);
    }

}

function encryptMessage(kabh, msg) { //falta retornar un iv(no he tokat res)
    try {
        let iv = bignum.rand(bignum(2).pow(128));
        let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(kabh, 'hex'), Buffer.from(iv.toString(16), 'hex'));
        let encrypted = cipher.update(msg, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return {
            iv: iv,
            encrypted: encrypted
        }
    } catch (e) {
        console.log(e);
    }

}

function readMessage(send) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    try {
        rl.question('Write a message to encrypt and send:', (msg) => {
            send(msg);
            console.log(`The message ${msg} is beeing sent...`);
            rl.close();
        });
    } catch (e) {
        console.log(e);
    }
}

readMessage(send); //1 line program ;)

module.exports = app;
