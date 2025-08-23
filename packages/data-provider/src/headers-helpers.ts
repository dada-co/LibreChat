import axios from 'axios';
axios.defaults.withCredentials = true;

export function setAcceptLanguageHeader(value: string): void {
  axios.defaults.headers.common['Accept-Language'] = value;
}

export function setTokenHeader(token: string) {
  axios.defaults.headers.common['Authorization'] = 'Bearer ' + token;
}
