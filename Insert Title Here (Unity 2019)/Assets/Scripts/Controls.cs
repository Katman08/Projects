using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Security.Cryptography;
using UnityEngine;

public class Controls : MonoBehaviour
{
    public float walkSpeed = 1f;
    public float sprintSpeed = 1f;
    public float jumpHeight = 1f;
    public float mouseSpeed = 1f;
    public Rigidbody player;
    public GameObject head;

    float speed = 1f;

    void Start()
    {
        Cursor.visible = false;
        Cursor.lockState = CursorLockMode.Locked;
    }

    void Update()
    {
        if (Input.GetKey("left shift")){
            speed = sprintSpeed; 
        }
        else
        {
            speed = walkSpeed;
        }

        if (Input.GetKey(KeyCode.F))
        {

            transform.rotation = Quaternion.Euler(0, 30, 0);
            player.velocity = new Vector3(0, 0, 0);
        }
        
        
        Vector3 location = transform.localPosition;
        if (Input.GetKey(KeyCode.W))
        {
            //player.AddForce(transform.forward * speed);
            location += transform.forward * speed;

        }
        if (Input.GetKey(KeyCode.S))
        {
            //player.AddForce(-transform.forward * speed);  
            location -= transform.forward * speed;
        }
        if (Input.GetKey(KeyCode.A))
        {
            //player.AddForce(-transform.right * speed);
            location -= transform.right * speed;
        }
        if (Input.GetKey(KeyCode.D))
        {
            //player.AddForce(transform.right * speed);
            location += transform.right * speed;
        }

        transform.localPosition = location;

        transform.Rotate(0, Input.GetAxis("Mouse X")*mouseSpeed, 0, Space.Self);

        head.transform.Rotate(Input.GetAxis("Mouse Y") * -mouseSpeed, 0, 0, Space.Self);

    }

    void OnCollisionStay(Collision collision)
    {
        if ((collision.gameObject.tag == "Floor") && (Input.GetKey("space")))
        {
            
            player.AddForce(transform.up * jumpHeight);
        }
    }
}

