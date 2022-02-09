package g46.kun.uz.service;

import g46.kun.uz.dto.AttachDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Calendar;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

@Service
public class AttachService {
    @Value("${image.url}")
    private String attachUrl;

    private final Path root = Paths.get("uploads");

    @PostConstruct
    public void init() {
        try {
            Files.createDirectory(root);
        } catch (FileAlreadyExistsException ex) {
            System.out.println("Folder already exists: " + root.getFileName());
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize folder for upload!");
        }
    }

    public AttachDTO saveToSystem(MultipartFile file) {
        try {
            // detail
            String datPath = getYmDString(); // 2021/07/13
            String fileOriginalName = datPath + UUID.randomUUID().toString() + file.getOriginalFilename();

            // 2021/07/13/aaaaasdasdasd/fileName.pgn

            File folder = new File("uploads/" + datPath); //  uploads/2021/07/13
            if (!folder.exists()) {
                folder.mkdirs();
            }

            String fileContentType = file.getContentType();
            String fileType = file.getContentType().split("/")[1];
            long size = file.getSize();
            byte[] imageByte = file.getBytes();
            // save to system
            Path path = this.root.resolve(fileOriginalName);

            Files.copy(file.getInputStream(), path);

            AttachDTO dto = new AttachDTO();
            dto.setOriginalName(fileOriginalName);
            dto.setContentType(fileContentType);
            dto.setSize(size);
            dto.setId(UUID.randomUUID().toString());
            dto.setUrl(attachUrl + fileOriginalName);

            return dto;
        } catch (Exception e) {
            throw new RuntimeException("Could not store the file. Error: " + e.getMessage());
        }
    }

    public Resource load(String filename) {
        try {
            Path file = root.resolve(filename);
            Resource resource = new UrlResource(file.toUri());

            if (resource.exists() || resource.isReadable()) {
                return resource;
            } else {
                throw new RuntimeException("Could not read the file!");
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException("Error: " + e.getMessage());
        }
    }

    public byte[] getImg(String imageName) {
        try {

            String path = "uploads/" + imageName;

            byte[] imageInByte;

            BufferedImage originalImage;
            try {
                originalImage = ImageIO.read(new File(path));
            } catch (Exception e) {
                return new byte[0];
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            ImageIO.write(originalImage, "png", baos);

            baos.flush();
            imageInByte = baos.toByteArray();
            baos.close();
            return imageInByte;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }


    public static String getYmDString() {
        int year = Calendar.getInstance().get(Calendar.YEAR);
        int month = Calendar.getInstance().get(Calendar.MONTH) + 1;
        int day = Calendar.getInstance().get(Calendar.DATE);

        return year + "/" + month + "/" + day + "/";
    }

    public void deleteAttach(Integer id) {
//        if (id == null) return;
//
//        Attach attach = this.getById(id);
//
//        String attachName = attach.getName();
//        String path = attach.getPath();
//
//        File file = new File(attachFolder + path + attachName);
//
//        if (file.exists()) {
//            file.delete();
//        }
    }
}
