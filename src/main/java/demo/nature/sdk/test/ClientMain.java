package demo.nature.sdk.test;


import demo.nature.sdk.fabric.FabricContext;
import demo.nature.sdk.fabric.MyFabricContext;

import java.nio.charset.StandardCharsets;

/**
 * @author nature
 * @date 5/9/2020 5:57 下午
 * @email 924943578@qq.com
 */
public class ClientMain {

    public static void main(String[] args) throws InterruptedException {
//       testFabricContext();
        testMyFabricContext();
    }

    public static void testMyFabricContext() throws InterruptedException {
        MyFabricContext context = new MyFabricContext();

        queryChainCode(context);
        invokeChainCode(context);
        queryChainCode(context);

        Thread.currentThread().join();
    }

    public static void testFabricContext() throws InterruptedException {
        FabricContext context = new FabricContext(false);

        queryChainCode(context);
//        invokeChainCode(context);
        queryChainCode(context);

        Thread.currentThread().join();
    }

    public static void queryChainCode(FabricContext context){
        byte[] bytes = context.queryChaincode("queryCar", "CAR0");
        String response = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("queryChainCode response: " + response);
    }

    public static void invokeChainCode(FabricContext context){
        byte[] bytes = context.invokeChaincode("changeCarOwner", "CAR0", "DDD");
        String response = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("invokeChainCode response: " + response);
    }


    public static void queryChainCode(MyFabricContext context){
        byte[] bytes = context.queryChaincode("queryCar", "CAR0");
        String response = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("queryChainCode response: " + response);
    }

    public static void invokeChainCode(MyFabricContext context){
        byte[] bytes = context.invokeChaincode("changeCarOwner", "CAR0", "FFF");
        String response = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("invokeChainCode response: " + response);
    }
}
