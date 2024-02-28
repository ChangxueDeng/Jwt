<script setup>

import router from "@/router/index.js";
</script>

<template>
  <div>
    <el-button @click="router.push('/')" plain type="warning">退出登陆</el-button>
  </div>
</template>

<style scoped>

</style>