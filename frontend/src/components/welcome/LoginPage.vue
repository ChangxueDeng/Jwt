<script setup>

import {Link, Lock, User} from "@element-plus/icons-vue";
import router from "@/router/index.js";
import {reactive} from "vue";
import {post} from "@/net/index.js";
import  {ElMessage} from "element-plus";

const form = reactive({
  username: '',
  password: '',
  remember: false
})
const login = ()=>{
  if(!form.username || !form.password){
   ElMessage.warning("请填写用户名和密码")
  }else {
    post("/api/auth/login",{
      username: form.username,
      password: form.password,
      remember: form.remember,
    }, (message)=>{
        ElMessage.success(message)
        router.push('/index')
    }, (message)=>{
      ElMessage.error(message)
    })
  }
}
</script>

<template>
  <div>
    <div>
      <div style="text-align: center">
        <h2 style="margin-top: 220px">登陆</h2>
        <el-text size="large">欢迎进行系统，请输入用户名和密码进行登陆</el-text>
      </div>
    </div>
    <div style="margin-top: 20px">
      <el-form style="margin: 20px;" :model="form">
        <el-form-item prop="username">
          <el-input placeholder="用户名" :prefix-icon="User" v-model="form.username"></el-input>
        </el-form-item>
        <el-form-item prop="password">
          <el-input placeholder="密码" :prefix-icon="Lock" v-model="form.password"></el-input>
        </el-form-item>
      </el-form>
      <div style="text-align: center; margin-top: 30px" >
        <el-row style="margin: 20px">
          <el-col style="text-align: left" :span="12">
            <el-checkbox v-model="form.remember" label="记住我"></el-checkbox>
          </el-col>
          <el-col style="text-align: right;" :span="12">
            <el-link @click="router.push('/forget')">忘记密码？</el-link>
          </el-col>
        </el-row>
        <el-button plain type="success" style="width: 190px;" @click="router.push('/index')" >立即登陆</el-button>
      </div>
    </div>
    <div>
      <el-divider >
        <el-text style="font-size: 14px">没有账户,</el-text>
        <el-link @click="router.push('/register')" style="margin-top: -3px; font-size: 15px" :icon="Link">进行注册</el-link>
      </el-divider>
    </div>
  </div>

</template>

<style scoped>

</style>