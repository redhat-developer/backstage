/*! For license information please see 1c9b6456.2a006275.js.LICENSE.txt */
"use strict";(self.webpackChunkbackstage_microsite=self.webpackChunkbackstage_microsite||[]).push([[906218],{101719:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>u,contentTitle:()=>c,default:()=>f,frontMatter:()=>o,metadata:()=>a,toc:()=>s});var n=r(824246),i=r(511151);const o={id:"backend-plugin-api.pluginservicefactoryconfig.initialization",title:"PluginServiceFactoryConfig.initialization",description:"API reference for PluginServiceFactoryConfig.initialization"},c=void 0,a={id:"reference/backend-plugin-api.pluginservicefactoryconfig.initialization",title:"PluginServiceFactoryConfig.initialization",description:"API reference for PluginServiceFactoryConfig.initialization",source:"@site/../docs/reference/backend-plugin-api.pluginservicefactoryconfig.initialization.md",sourceDirName:"reference",slug:"/reference/backend-plugin-api.pluginservicefactoryconfig.initialization",permalink:"/docs/reference/backend-plugin-api.pluginservicefactoryconfig.initialization",draft:!1,unlisted:!1,editUrl:"https://github.com/backstage/backstage/edit/master/docs/../docs/reference/backend-plugin-api.pluginservicefactoryconfig.initialization.md",tags:[],version:"current",frontMatter:{id:"backend-plugin-api.pluginservicefactoryconfig.initialization",title:"PluginServiceFactoryConfig.initialization",description:"API reference for PluginServiceFactoryConfig.initialization"}},u={},s=[{value:"Remarks",id:"remarks",level:2}];function l(e){const t={a:"a",code:"code",h2:"h2",li:"li",p:"p",pre:"pre",strong:"strong",ul:"ul",...(0,i.a)(),...e.components};return(0,n.jsxs)(n.Fragment,{children:[(0,n.jsxs)(t.p,{children:[(0,n.jsx)(t.a,{href:"/docs/reference/",children:"Home"})," > ",(0,n.jsx)(t.a,{href:"/docs/reference/backend-plugin-api",children:(0,n.jsx)(t.code,{children:"@backstage/backend-plugin-api"})})," > ",(0,n.jsx)(t.a,{href:"/docs/reference/backend-plugin-api.pluginservicefactoryconfig",children:(0,n.jsx)(t.code,{children:"PluginServiceFactoryConfig"})})," > ",(0,n.jsx)(t.a,{href:"/docs/reference/backend-plugin-api.pluginservicefactoryconfig.initialization",children:(0,n.jsx)(t.code,{children:"initialization"})})]}),"\n",(0,n.jsxs)(t.p,{children:["The initialization strategy for the service factory. This service is plugin scoped and will use ",(0,n.jsx)(t.code,{children:"lazy"})," by default."]}),"\n",(0,n.jsx)(t.p,{children:(0,n.jsx)(t.strong,{children:"Signature:"})}),"\n",(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-typescript",children:"initialization?: 'always' | 'lazy';\n"})}),"\n",(0,n.jsx)(t.h2,{id:"remarks",children:"Remarks"}),"\n",(0,n.jsxs)(t.ul,{children:["\n",(0,n.jsxs)(t.li,{children:[(0,n.jsx)(t.code,{children:"always"})," - The service will always be initialized regardless if it is used or not. - ",(0,n.jsx)(t.code,{children:"lazy"})," - The service will only be initialized if it is depended on by a different service or feature."]}),"\n"]}),"\n",(0,n.jsxs)(t.p,{children:["Service factories for root scoped services use ",(0,n.jsx)(t.code,{children:"always"})," as the default, while plugin scoped services use ",(0,n.jsx)(t.code,{children:"lazy"}),"."]})]})}function f(e={}){const{wrapper:t}={...(0,i.a)(),...e.components};return t?(0,n.jsx)(t,{...e,children:(0,n.jsx)(l,{...e})}):l(e)}},371426:(e,t,r)=>{var n=r(827378),i=Symbol.for("react.element"),o=Symbol.for("react.fragment"),c=Object.prototype.hasOwnProperty,a=n.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner,u={key:!0,ref:!0,__self:!0,__source:!0};function s(e,t,r){var n,o={},s=null,l=null;for(n in void 0!==r&&(s=""+r),void 0!==t.key&&(s=""+t.key),void 0!==t.ref&&(l=t.ref),t)c.call(t,n)&&!u.hasOwnProperty(n)&&(o[n]=t[n]);if(e&&e.defaultProps)for(n in t=e.defaultProps)void 0===o[n]&&(o[n]=t[n]);return{$$typeof:i,type:e,key:s,ref:l,props:o,_owner:a.current}}t.Fragment=o,t.jsx=s,t.jsxs=s},541535:(e,t)=>{var r=Symbol.for("react.element"),n=Symbol.for("react.portal"),i=Symbol.for("react.fragment"),o=Symbol.for("react.strict_mode"),c=Symbol.for("react.profiler"),a=Symbol.for("react.provider"),u=Symbol.for("react.context"),s=Symbol.for("react.forward_ref"),l=Symbol.for("react.suspense"),f=Symbol.for("react.memo"),p=Symbol.for("react.lazy"),d=Symbol.iterator;var y={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},h=Object.assign,g={};function v(e,t,r){this.props=e,this.context=t,this.refs=g,this.updater=r||y}function m(){}function b(e,t,r){this.props=e,this.context=t,this.refs=g,this.updater=r||y}v.prototype.isReactComponent={},v.prototype.setState=function(e,t){if("object"!=typeof e&&"function"!=typeof e&&null!=e)throw Error("setState(...): takes an object of state variables to update or a function which returns an object of state variables.");this.updater.enqueueSetState(this,e,t,"setState")},v.prototype.forceUpdate=function(e){this.updater.enqueueForceUpdate(this,e,"forceUpdate")},m.prototype=v.prototype;var _=b.prototype=new m;_.constructor=b,h(_,v.prototype),_.isPureReactComponent=!0;var k=Array.isArray,S=Object.prototype.hasOwnProperty,j={current:null},x={key:!0,ref:!0,__self:!0,__source:!0};function w(e,t,n){var i,o={},c=null,a=null;if(null!=t)for(i in void 0!==t.ref&&(a=t.ref),void 0!==t.key&&(c=""+t.key),t)S.call(t,i)&&!x.hasOwnProperty(i)&&(o[i]=t[i]);var u=arguments.length-2;if(1===u)o.children=n;else if(1<u){for(var s=Array(u),l=0;l<u;l++)s[l]=arguments[l+2];o.children=s}if(e&&e.defaultProps)for(i in u=e.defaultProps)void 0===o[i]&&(o[i]=u[i]);return{$$typeof:r,type:e,key:c,ref:a,props:o,_owner:j.current}}function C(e){return"object"==typeof e&&null!==e&&e.$$typeof===r}var E=/\/+/g;function R(e,t){return"object"==typeof e&&null!==e&&null!=e.key?function(e){var t={"=":"=0",":":"=2"};return"$"+e.replace(/[=:]/g,(function(e){return t[e]}))}(""+e.key):t.toString(36)}function P(e,t,i,o,c){var a=typeof e;"undefined"!==a&&"boolean"!==a||(e=null);var u=!1;if(null===e)u=!0;else switch(a){case"string":case"number":u=!0;break;case"object":switch(e.$$typeof){case r:case n:u=!0}}if(u)return c=c(u=e),e=""===o?"."+R(u,0):o,k(c)?(i="",null!=e&&(i=e.replace(E,"$&/")+"/"),P(c,t,i,"",(function(e){return e}))):null!=c&&(C(c)&&(c=function(e,t){return{$$typeof:r,type:e.type,key:t,ref:e.ref,props:e.props,_owner:e._owner}}(c,i+(!c.key||u&&u.key===c.key?"":(""+c.key).replace(E,"$&/")+"/")+e)),t.push(c)),1;if(u=0,o=""===o?".":o+":",k(e))for(var s=0;s<e.length;s++){var l=o+R(a=e[s],s);u+=P(a,t,i,l,c)}else if(l=function(e){return null===e||"object"!=typeof e?null:"function"==typeof(e=d&&e[d]||e["@@iterator"])?e:null}(e),"function"==typeof l)for(e=l.call(e),s=0;!(a=e.next()).done;)u+=P(a=a.value,t,i,l=o+R(a,s++),c);else if("object"===a)throw t=String(e),Error("Objects are not valid as a React child (found: "+("[object Object]"===t?"object with keys {"+Object.keys(e).join(", ")+"}":t)+"). If you meant to render a collection of children, use an array instead.");return u}function z(e,t,r){if(null==e)return e;var n=[],i=0;return P(e,n,"","",(function(e){return t.call(r,e,i++)})),n}function $(e){if(-1===e._status){var t=e._result;(t=t()).then((function(t){0!==e._status&&-1!==e._status||(e._status=1,e._result=t)}),(function(t){0!==e._status&&-1!==e._status||(e._status=2,e._result=t)})),-1===e._status&&(e._status=0,e._result=t)}if(1===e._status)return e._result.default;throw e._result}var O={current:null},I={transition:null},F={ReactCurrentDispatcher:O,ReactCurrentBatchConfig:I,ReactCurrentOwner:j};t.Children={map:z,forEach:function(e,t,r){z(e,(function(){t.apply(this,arguments)}),r)},count:function(e){var t=0;return z(e,(function(){t++})),t},toArray:function(e){return z(e,(function(e){return e}))||[]},only:function(e){if(!C(e))throw Error("React.Children.only expected to receive a single React element child.");return e}},t.Component=v,t.Fragment=i,t.Profiler=c,t.PureComponent=b,t.StrictMode=o,t.Suspense=l,t.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=F,t.cloneElement=function(e,t,n){if(null==e)throw Error("React.cloneElement(...): The argument must be a React element, but you passed "+e+".");var i=h({},e.props),o=e.key,c=e.ref,a=e._owner;if(null!=t){if(void 0!==t.ref&&(c=t.ref,a=j.current),void 0!==t.key&&(o=""+t.key),e.type&&e.type.defaultProps)var u=e.type.defaultProps;for(s in t)S.call(t,s)&&!x.hasOwnProperty(s)&&(i[s]=void 0===t[s]&&void 0!==u?u[s]:t[s])}var s=arguments.length-2;if(1===s)i.children=n;else if(1<s){u=Array(s);for(var l=0;l<s;l++)u[l]=arguments[l+2];i.children=u}return{$$typeof:r,type:e.type,key:o,ref:c,props:i,_owner:a}},t.createContext=function(e){return(e={$$typeof:u,_currentValue:e,_currentValue2:e,_threadCount:0,Provider:null,Consumer:null,_defaultValue:null,_globalName:null}).Provider={$$typeof:a,_context:e},e.Consumer=e},t.createElement=w,t.createFactory=function(e){var t=w.bind(null,e);return t.type=e,t},t.createRef=function(){return{current:null}},t.forwardRef=function(e){return{$$typeof:s,render:e}},t.isValidElement=C,t.lazy=function(e){return{$$typeof:p,_payload:{_status:-1,_result:e},_init:$}},t.memo=function(e,t){return{$$typeof:f,type:e,compare:void 0===t?null:t}},t.startTransition=function(e){var t=I.transition;I.transition={};try{e()}finally{I.transition=t}},t.unstable_act=function(){throw Error("act(...) is not supported in production builds of React.")},t.useCallback=function(e,t){return O.current.useCallback(e,t)},t.useContext=function(e){return O.current.useContext(e)},t.useDebugValue=function(){},t.useDeferredValue=function(e){return O.current.useDeferredValue(e)},t.useEffect=function(e,t){return O.current.useEffect(e,t)},t.useId=function(){return O.current.useId()},t.useImperativeHandle=function(e,t,r){return O.current.useImperativeHandle(e,t,r)},t.useInsertionEffect=function(e,t){return O.current.useInsertionEffect(e,t)},t.useLayoutEffect=function(e,t){return O.current.useLayoutEffect(e,t)},t.useMemo=function(e,t){return O.current.useMemo(e,t)},t.useReducer=function(e,t,r){return O.current.useReducer(e,t,r)},t.useRef=function(e){return O.current.useRef(e)},t.useState=function(e){return O.current.useState(e)},t.useSyncExternalStore=function(e,t,r){return O.current.useSyncExternalStore(e,t,r)},t.useTransition=function(){return O.current.useTransition()},t.version="18.2.0"},827378:(e,t,r)=>{e.exports=r(541535)},824246:(e,t,r)=>{e.exports=r(371426)},511151:(e,t,r)=>{r.d(t,{Z:()=>a,a:()=>c});var n=r(667294);const i={},o=n.createContext(i);function c(e){const t=n.useContext(o);return n.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function a(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(i):e.components||i:c(e.components),n.createElement(o.Provider,{value:t},e.children)}}}]);