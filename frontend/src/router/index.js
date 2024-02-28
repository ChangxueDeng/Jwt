import {createRouter ,createWebHistory} from "vue-router";

const routes = [
    {
        path: '/',
        name: 'welcome',
        component: () => import("@/views/WelcomePage.vue"),
        children:[
            {
                path: '',
                name: 'welcome-login',
                component: () => import("@/components/welcome/LoginPage.vue")
            },
            {
                path: '/register',
                name: 'welcome-register',
                component: () => import("@/components/welcome/RegisterPaga.vue")
            },
            {
                path: '/forget',
                name: 'welcome-forget',
                component: () => import("@/components/welcome/ForgetPage.vue"),
            }
        ]
    },
    {
        path: '/index',
        name: 'index',
        component: () => import("@/views/IndexPage.vue")
    }
]

const router = createRouter({
    history: createWebHistory(),
    routes,
})

export default router