import path from 'path';
import express from 'express';
import { Configuration, Provider } from 'oidc-provider';

const app = express(); 

app.use(express.static(__dirname + '/public'));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');



const configuration: Configuration = {
  clients: [
    {
      client_id: process.env.GOOGLE_CLIENT_ID as string,
      client_secret: process.env.GOOGLE_SECRET,
      grant_types: ['authorization_code'],
      redirect_uris: ['http://localhost:8080/auth/login/callback'],
      response_types: ['code'],
    },
  ],
  pkce: {
    required: () => false,
  },
};

const oidc = new Provider('http://localhost:3000', configuration);

app.use('/oidc', oidc.callback());

app.listen(3000, () => {
  console.log('\n\tlisten on port 3000');
});
