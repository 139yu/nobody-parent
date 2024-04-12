package com.xj.demo.servlet;

import org.springframework.stereotype.Component;

import javax.servlet.AsyncContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Component
@WebServlet(urlPatterns = "/test", asyncSupported = true)
public class TestServlet extends HttpServlet {
    private final static int AVAILABLE_PROCESSORS = Runtime.getRuntime().availableProcessors();
    private final static ThreadPoolExecutor EXECUTOR = new ThreadPoolExecutor(AVAILABLE_PROCESSORS, AVAILABLE_PROCESSORS * 2, 1, TimeUnit.SECONDS, new LinkedBlockingQueue<>(5), new ThreadPoolExecutor.CallerRunsPolicy());

    /*@Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        final AsyncContext asyncContext = req.startAsync();
        ServletInputStream inputStream = req.getInputStream();
        //设置数据就绪监听器
        inputStream.setReadListener(new ReadListener() {
            /**
             * 数据就绪
             * @throws IOException
             *//*
            @Override
            public void onDataAvailable() throws IOException {

            }

            /**
             * 读取完数据，返回响应
             * @throws IOException
             *//*
            @Override
            public void onAllDataRead() throws IOException {

            }

            @Override
            public void onError(Throwable throwable) {

            }
        });
    }*/

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        final AsyncContext asyncContext = req.startAsync();
        EXECUTOR.execute(() -> {
            try {
                System.out.println("----async res begin----");
                try {
                    long start = System.currentTimeMillis();
                    final ServletInputStream inputStream = asyncContext.getRequest().getInputStream();
                    byte buffer[] = new byte[1024];
                    int readBytes = 0;
                    int total = 0;
                    while ((readBytes = inputStream.read(buffer)) > 0) {
                        total += readBytes;
                    }
                    long cost = System.currentTimeMillis() - start;
                    System.out.println(Thread.currentThread().getName() + " Read: " + total + " bytes,cost: " + cost);

                } catch (IOException e) {
                    e.printStackTrace();
                }
                Thread.sleep(3000);
                resp.setContentType("application/json");
                resp.setStatus(HttpServletResponse.SC_OK);
                resp.setCharacterEncoding("UTF-8");
                resp.getWriter().write("厚礼蟹");
            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
            }finally {
                asyncContext.complete();
            }
            System.out.println("----async res end----");
        });
        asyncContext.start(()->{
            System.out.println("--------start async-------");
            try {
                Thread.sleep(3000);
                resp.setContentType("application/json");
                resp.setStatus(HttpServletResponse.SC_OK);
                resp.setCharacterEncoding("UTF-8");
                resp.getWriter().write("厚礼蟹");
                System.out.println("--------end async-------");
            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
            }finally {
                asyncContext.complete();
            }
        });
    }

}
