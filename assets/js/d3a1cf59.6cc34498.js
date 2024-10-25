/*! For license information please see d3a1cf59.6cc34498.js.LICENSE.txt */
"use strict";(self.webpackChunkbackstage_microsite=self.webpackChunkbackstage_microsite||[]).push([[690070],{369649:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>u,contentTitle:()=>a,default:()=>f,frontMatter:()=>c,metadata:()=>s,toc:()=>l});var o=r(824246),n=r(511151);const c={id:"plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactoryoptions",title:"StackOverflowQuestionsCollatorFactoryOptions",description:"API reference for StackOverflowQuestionsCollatorFactoryOptions"},a=void 0,s={id:"reference/plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactoryoptions",title:"StackOverflowQuestionsCollatorFactoryOptions",description:"API reference for StackOverflowQuestionsCollatorFactoryOptions",source:"@site/../docs/reference/plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactoryoptions.md",sourceDirName:"reference",slug:"/reference/plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactoryoptions",permalink:"/docs/reference/plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactoryoptions",draft:!1,unlisted:!1,editUrl:"https://github.com/backstage/backstage/edit/master/docs/../docs/reference/plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactoryoptions.md",tags:[],version:"current",frontMatter:{id:"plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactoryoptions",title:"StackOverflowQuestionsCollatorFactoryOptions",description:"API reference for StackOverflowQuestionsCollatorFactoryOptions"}},u={},l=[];function i(e){const t={a:"a",code:"code",p:"p",pre:"pre",strong:"strong",...(0,n.a)(),...e.components};return(0,o.jsxs)(o.Fragment,{children:[(0,o.jsxs)(t.p,{children:[(0,o.jsx)(t.a,{href:"/docs/reference/",children:"Home"})," > ",(0,o.jsx)(t.a,{href:"/docs/reference/plugin-search-backend-module-stack-overflow-collator",children:(0,o.jsx)(t.code,{children:"@backstage/plugin-search-backend-module-stack-overflow-collator"})})," > ",(0,o.jsx)(t.a,{href:"/docs/reference/plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactoryoptions",children:(0,o.jsx)(t.code,{children:"StackOverflowQuestionsCollatorFactoryOptions"})})]}),"\n",(0,o.jsxs)(t.p,{children:["Options for ",(0,o.jsx)(t.a,{href:"/docs/reference/plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionscollatorfactory",children:"StackOverflowQuestionsCollatorFactory"})]}),"\n",(0,o.jsx)(t.p,{children:(0,o.jsx)(t.strong,{children:"Signature:"})}),"\n",(0,o.jsx)(t.pre,{children:(0,o.jsx)(t.code,{className:"language-typescript",children:"export type StackOverflowQuestionsCollatorFactoryOptions = {\n    baseUrl?: string;\n    maxPage?: number;\n    apiKey?: string;\n    apiAccessToken?: string;\n    teamName?: string;\n    requestParams?: StackOverflowQuestionsRequestParams;\n    logger: LoggerService;\n};\n"})}),"\n",(0,o.jsxs)(t.p,{children:[(0,o.jsx)(t.strong,{children:"References:"})," ",(0,o.jsx)(t.a,{href:"/docs/reference/plugin-search-backend-module-stack-overflow-collator.stackoverflowquestionsrequestparams",children:"StackOverflowQuestionsRequestParams"}),", ",(0,o.jsx)(t.a,{href:"/docs/reference/backend-plugin-api.loggerservice",children:"LoggerService"})]})]})}function f(e={}){const{wrapper:t}={...(0,n.a)(),...e.components};return t?(0,o.jsx)(t,{...e,children:(0,o.jsx)(i,{...e})}):i(e)}},371426:(e,t,r)=>{var o=r(827378),n=Symbol.for("react.element"),c=Symbol.for("react.fragment"),a=Object.prototype.hasOwnProperty,s=o.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner,u={key:!0,ref:!0,__self:!0,__source:!0};function l(e,t,r){var o,c={},l=null,i=null;for(o in void 0!==r&&(l=""+r),void 0!==t.key&&(l=""+t.key),void 0!==t.ref&&(i=t.ref),t)a.call(t,o)&&!u.hasOwnProperty(o)&&(c[o]=t[o]);if(e&&e.defaultProps)for(o in t=e.defaultProps)void 0===c[o]&&(c[o]=t[o]);return{$$typeof:n,type:e,key:l,ref:i,props:c,_owner:s.current}}t.Fragment=c,t.jsx=l,t.jsxs=l},541535:(e,t)=>{var r=Symbol.for("react.element"),o=Symbol.for("react.portal"),n=Symbol.for("react.fragment"),c=Symbol.for("react.strict_mode"),a=Symbol.for("react.profiler"),s=Symbol.for("react.provider"),u=Symbol.for("react.context"),l=Symbol.for("react.forward_ref"),i=Symbol.for("react.suspense"),f=Symbol.for("react.memo"),p=Symbol.for("react.lazy"),d=Symbol.iterator;var y={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},h=Object.assign,v={};function m(e,t,r){this.props=e,this.context=t,this.refs=v,this.updater=r||y}function k(){}function b(e,t,r){this.props=e,this.context=t,this.refs=v,this.updater=r||y}m.prototype.isReactComponent={},m.prototype.setState=function(e,t){if("object"!=typeof e&&"function"!=typeof e&&null!=e)throw Error("setState(...): takes an object of state variables to update or a function which returns an object of state variables.");this.updater.enqueueSetState(this,e,t,"setState")},m.prototype.forceUpdate=function(e){this.updater.enqueueForceUpdate(this,e,"forceUpdate")},k.prototype=m.prototype;var _=b.prototype=new k;_.constructor=b,h(_,m.prototype),_.isPureReactComponent=!0;var w=Array.isArray,g=Object.prototype.hasOwnProperty,S={current:null},O={key:!0,ref:!0,__self:!0,__source:!0};function x(e,t,o){var n,c={},a=null,s=null;if(null!=t)for(n in void 0!==t.ref&&(s=t.ref),void 0!==t.key&&(a=""+t.key),t)g.call(t,n)&&!O.hasOwnProperty(n)&&(c[n]=t[n]);var u=arguments.length-2;if(1===u)c.children=o;else if(1<u){for(var l=Array(u),i=0;i<u;i++)l[i]=arguments[i+2];c.children=l}if(e&&e.defaultProps)for(n in u=e.defaultProps)void 0===c[n]&&(c[n]=u[n]);return{$$typeof:r,type:e,key:a,ref:s,props:c,_owner:S.current}}function j(e){return"object"==typeof e&&null!==e&&e.$$typeof===r}var C=/\/+/g;function E(e,t){return"object"==typeof e&&null!==e&&null!=e.key?function(e){var t={"=":"=0",":":"=2"};return"$"+e.replace(/[=:]/g,(function(e){return t[e]}))}(""+e.key):t.toString(36)}function R(e,t,n,c,a){var s=typeof e;"undefined"!==s&&"boolean"!==s||(e=null);var u=!1;if(null===e)u=!0;else switch(s){case"string":case"number":u=!0;break;case"object":switch(e.$$typeof){case r:case o:u=!0}}if(u)return a=a(u=e),e=""===c?"."+E(u,0):c,w(a)?(n="",null!=e&&(n=e.replace(C,"$&/")+"/"),R(a,t,n,"",(function(e){return e}))):null!=a&&(j(a)&&(a=function(e,t){return{$$typeof:r,type:e.type,key:t,ref:e.ref,props:e.props,_owner:e._owner}}(a,n+(!a.key||u&&u.key===a.key?"":(""+a.key).replace(C,"$&/")+"/")+e)),t.push(a)),1;if(u=0,c=""===c?".":c+":",w(e))for(var l=0;l<e.length;l++){var i=c+E(s=e[l],l);u+=R(s,t,n,i,a)}else if(i=function(e){return null===e||"object"!=typeof e?null:"function"==typeof(e=d&&e[d]||e["@@iterator"])?e:null}(e),"function"==typeof i)for(e=i.call(e),l=0;!(s=e.next()).done;)u+=R(s=s.value,t,n,i=c+E(s,l++),a);else if("object"===s)throw t=String(e),Error("Objects are not valid as a React child (found: "+("[object Object]"===t?"object with keys {"+Object.keys(e).join(", ")+"}":t)+"). If you meant to render a collection of children, use an array instead.");return u}function P(e,t,r){if(null==e)return e;var o=[],n=0;return R(e,o,"","",(function(e){return t.call(r,e,n++)})),o}function $(e){if(-1===e._status){var t=e._result;(t=t()).then((function(t){0!==e._status&&-1!==e._status||(e._status=1,e._result=t)}),(function(t){0!==e._status&&-1!==e._status||(e._status=2,e._result=t)})),-1===e._status&&(e._status=0,e._result=t)}if(1===e._status)return e._result.default;throw e._result}var q={current:null},F={transition:null},I={ReactCurrentDispatcher:q,ReactCurrentBatchConfig:F,ReactCurrentOwner:S};t.Children={map:P,forEach:function(e,t,r){P(e,(function(){t.apply(this,arguments)}),r)},count:function(e){var t=0;return P(e,(function(){t++})),t},toArray:function(e){return P(e,(function(e){return e}))||[]},only:function(e){if(!j(e))throw Error("React.Children.only expected to receive a single React element child.");return e}},t.Component=m,t.Fragment=n,t.Profiler=a,t.PureComponent=b,t.StrictMode=c,t.Suspense=i,t.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=I,t.cloneElement=function(e,t,o){if(null==e)throw Error("React.cloneElement(...): The argument must be a React element, but you passed "+e+".");var n=h({},e.props),c=e.key,a=e.ref,s=e._owner;if(null!=t){if(void 0!==t.ref&&(a=t.ref,s=S.current),void 0!==t.key&&(c=""+t.key),e.type&&e.type.defaultProps)var u=e.type.defaultProps;for(l in t)g.call(t,l)&&!O.hasOwnProperty(l)&&(n[l]=void 0===t[l]&&void 0!==u?u[l]:t[l])}var l=arguments.length-2;if(1===l)n.children=o;else if(1<l){u=Array(l);for(var i=0;i<l;i++)u[i]=arguments[i+2];n.children=u}return{$$typeof:r,type:e.type,key:c,ref:a,props:n,_owner:s}},t.createContext=function(e){return(e={$$typeof:u,_currentValue:e,_currentValue2:e,_threadCount:0,Provider:null,Consumer:null,_defaultValue:null,_globalName:null}).Provider={$$typeof:s,_context:e},e.Consumer=e},t.createElement=x,t.createFactory=function(e){var t=x.bind(null,e);return t.type=e,t},t.createRef=function(){return{current:null}},t.forwardRef=function(e){return{$$typeof:l,render:e}},t.isValidElement=j,t.lazy=function(e){return{$$typeof:p,_payload:{_status:-1,_result:e},_init:$}},t.memo=function(e,t){return{$$typeof:f,type:e,compare:void 0===t?null:t}},t.startTransition=function(e){var t=F.transition;F.transition={};try{e()}finally{F.transition=t}},t.unstable_act=function(){throw Error("act(...) is not supported in production builds of React.")},t.useCallback=function(e,t){return q.current.useCallback(e,t)},t.useContext=function(e){return q.current.useContext(e)},t.useDebugValue=function(){},t.useDeferredValue=function(e){return q.current.useDeferredValue(e)},t.useEffect=function(e,t){return q.current.useEffect(e,t)},t.useId=function(){return q.current.useId()},t.useImperativeHandle=function(e,t,r){return q.current.useImperativeHandle(e,t,r)},t.useInsertionEffect=function(e,t){return q.current.useInsertionEffect(e,t)},t.useLayoutEffect=function(e,t){return q.current.useLayoutEffect(e,t)},t.useMemo=function(e,t){return q.current.useMemo(e,t)},t.useReducer=function(e,t,r){return q.current.useReducer(e,t,r)},t.useRef=function(e){return q.current.useRef(e)},t.useState=function(e){return q.current.useState(e)},t.useSyncExternalStore=function(e,t,r){return q.current.useSyncExternalStore(e,t,r)},t.useTransition=function(){return q.current.useTransition()},t.version="18.2.0"},827378:(e,t,r)=>{e.exports=r(541535)},824246:(e,t,r)=>{e.exports=r(371426)},511151:(e,t,r)=>{r.d(t,{Z:()=>s,a:()=>a});var o=r(667294);const n={},c=o.createContext(n);function a(e){const t=o.useContext(c);return o.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function s(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(n):e.components||n:a(e.components),o.createElement(c.Provider,{value:t},e.children)}}}]);