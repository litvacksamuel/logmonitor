const express = require('express');
const fs = require('fs');
const readlastlines = require('read-last-lines');
const path = require('path');
const axios = require('axios');
const { exec } = require("child_process");
const uaparser = require("ua-parser-js");

const file = path.join(__dirname, "test.txt");

var app = express();

var server = app.listen(8080, () => {
    console.log('Server up');
});

const io = require('socket.io')(server, {
    cors: {
        origin: '*',
    }
});

io.on('connection', (socket) => {
    socket.on('blockipaction', (data) => {
        exec("sudo iptables -I INPUT -s " + data.ip + " -j DROP");
        exec("sudo service iptables save");
    });

    socket.on('unblockipaction', (data) => {
        exec("sudo iptables -D INPUT -s " + data.ip + "  -j DROP");
        exec("sudo service iptables save");
    });

    socket.on('checkrootpassword', (password) => {
        exec('echo "' + password + '" | sudo -S id', (error, stdout, stderr) => {
            if(!error){
                socket.emit('sudoenabled');
            } else {
                socket.emit('accessdenied');
            }
        });
    });
});

if(fs.existsSync(file)) {
    fs.watchFile(file, { persistent: true, interval: 1000 }, function(){
        readlastlines.read(file, 1).then((lines) => {
            var ip = lines.substr(0, lines.indexOf('-'));
            var ipclean = ip.trim();
            var date = lines.substring(
                lines.indexOf("[") + 1, 
                lines.lastIndexOf("]")
            );

            date = date.substring(0, 11) + ' ' + date.substring(11 + 1);
            date = date.substring(0,20);
            date = date.split('/').join('-')

            exec('sudo iptables -L INPUT -n -v | grep -w "' + ipclean + '"', (error1, stdout1, stderr1) => {
                exec("echo '" + lines + "' | awk -F\\\" '{print $6}'", (error2, stdout2, stderr2) => {
                    const isProxy = axios.get('https://api.ip2proxy.com/?ip=' + ipclean + '&key=VEEY4VETQ5&package=PX1');
                    const ipWhois = axios.get('http://ip-api.com/json/' + ipclean);
                    
                    var ua = null;
                    ua = stdout2;
                    var osbrowser = uaparser(ua);
                    var risk = 'Low';
                    var request_type = 'Normal';
                    
                    if(osbrowser.os.name){
                        osbrowser = osbrowser.os.name + ' ' + osbrowser.os.version + ' / ' + osbrowser.browser.name;
                    } else {
                        osbrowser = ua;
                        risk = 'Medium';
                        request_type = 'Possible BOT';
                    }
                
                    exec("echo '" + lines + "' | tr '[:upper:]' '[:lower:]' | awk -F\\\" '{print $2}'", (error3, stdout3, stderr3) => {
                        
                        if(stdout3.includes('select') || stdout3.includes('union') || stdout3.includes('concat(') || stdout3.includes('version(') || stdout3.includes('un/*')){
                            risk = 'High';
                            request_type = 'Possible SQLi';
                        }
                    
                        if(stdout3.includes('alert(') || stdout3.includes('alert\\') || stdout3.includes('script') || stdout3.includes('fromCharCode') || stdout3.includes('&#')){
                            risk = 'High';
                            request_type = 'Possible XSS';
                        }
                        
                        var tdrisk = '<td bgcolor="#76f05d">' + risk + '</td>'
                        
                        if(risk == 'Medium'){
                            tdrisk = '<td bgcolor="#eaf255">' + risk + '</td>';
                        } else if(risk == 'High'){
                            tdrisk = '<td bgcolor="#fc1c1c">' + risk + '</td>'
                        }
                    
                        axios.all([isProxy, ipWhois]).then(axios.spread((...responses) => {
                            var proxy = responses[0].data.isProxy;
                            var country = responses[1].data.country;
                            var countryCode = responses[1].data.countryCode;
                            var countryIcon = '<img width="30" alt="' + country + '" src="http://purecatamphetamine.github.io/country-flag-icons/3x2/' + countryCode + '.svg"/>';
                            var isporg = responses[1].data.org;
                            var newtd = '<tr><td>' + ipclean + '</td><td>' + date + '</td><td>' + countryIcon + ' ' + country + '</td><td>' + osbrowser + '</td><td>' + proxy + '</td><td>' + isporg + '</td><td>' + request_type + '</td><td>' + tdrisk + '</td></tr>';
                            io.emit('filechanged', { text: newtd });
                        }));
                    });
                });
            });
        });
    });
}

module.exports = app;
