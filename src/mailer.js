import nodemailer from 'nodemailer';
import { config } from './config.js';

let transporter;

function getTransporter() {
  if (transporter) return transporter;
  if (config.mail.transport === 'console') {
    // Somente desenvolvimento (config.js recusa isso em producao):
    // gera a mensagem sem enviar e a imprime no terminal.
    transporter = nodemailer.createTransport({ streamTransport: true, buffer: true, newline: 'unix' });
  } else {
    transporter = nodemailer.createTransport({
      host: config.mail.host,
      port: config.mail.port,
      secure: config.mail.port === 465,
      requireTLS: config.mail.port !== 465, // STARTTLS obrigatorio, nunca texto puro
      auth: config.mail.user ? { user: config.mail.user, pass: config.mail.pass } : undefined,
    });
  }
  return transporter;
}

export async function sendMail({ to, subject, text }) {
  const info = await getTransporter().sendMail({ from: config.mail.from, to, subject, text });
  if (config.mail.transport === 'console') {
    console.log('----- [DEV] e-mail nao enviado (MAIL_TRANSPORT=console) -----');
    console.log(info.message.toString());
    console.log('--------------------------------------------------------------');
  }
}
