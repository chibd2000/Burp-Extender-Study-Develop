package burp.utils;

import org.junit.Test;

import java.text.SimpleDateFormat;
import java.util.Date;

public class TimeOutput {
    private static SimpleDateFormat simpleDateFormat;

    static{
        simpleDateFormat = new SimpleDateFormat("[yyyy-MM-dd HH:mm:ss]");
    }

    public static String formatOutput(String s){
        Date date = new Date();
        return simpleDateFormat.format(date.getTime()) + " " + s;
    }

    @Test
    public void test10(){
        String s = TimeOutput.formatOutput("1111");
        System.out.println(s);
    }
}
