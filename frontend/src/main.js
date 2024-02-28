import { createApp } from 'vue'
import App from './App.vue'
import router from "@/router/index.js";
import 'element-plus/dist/index.css'
import axios from "axios";
const app = createApp(App)
axios.defaults.baseURL = 'http://localhost:8081'
app.use(router)
app.mount("#app")
