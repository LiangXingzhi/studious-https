package studious.https.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class FileUtils
{
    static Logger logger = LoggerFactory.getLogger(FileUtils.class);

    public static String getBasePath()
    {
        return FileUtils.class.getClassLoader().getResource("").getPath();
    }

    public static List<String> listFiles(String contextPath)
    {
        File contextDir = new File(
                getBasePath() + File.separator + contextPath);
        List<String> files = new ArrayList<String>();
        if (contextDir.isDirectory())
        {
            files.addAll(Arrays.asList(contextDir.list()));
        }
        return files;
    }

    public static void main(String[] args)
    {
        System.out.println(listFiles("ecm"));
        System.out.println("/get/vnfpackages/-/deploy"
                .matches("/get/vnfpackages/[a-zA-Z0-9-]+/deploy"));
    }

    public static String getFileByUrl(String resourceBase, String path)
    {
        logger.info("find file by url for URL:[" + path
                + "] with resource base:[" + resourceBase + "]");
        Optional<String> fileNameOptional = listFiles(resourceBase).stream()
                .filter(fileName -> {
                    String regex = fileName.replace(".json", "")
                            .replace('.', '/')
                            .replace("TEMPID", "[a-zA-Z0-9-]+");
                    return path.matches(regex);
                }).findFirst();
        return getBasePath() + resourceBase + File.separator
                + fileNameOptional.orElse("default.json");
    }
}
