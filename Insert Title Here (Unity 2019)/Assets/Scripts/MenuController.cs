using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;
using UnityEngine.SceneManagement;

namespace Mirror
{

    public class MenuController : MonoBehaviour
    {
        public NetworkManager manager;
        public GameObject InputBox;
        public Text IPInput;
        public GameObject IPSubmit;

        public void Start()
        {
            InputBox.SetActive(false);
            IPSubmit.SetActive(false);
        }

        public void SinglePlayer()
        {

            SceneManager.LoadScene("SinglePlayer");
        }

        public void JoinServer()
        {
            
            InputBox.SetActive(true);
            IPSubmit.SetActive(true);
        }

        public void IPSubmitButton()
        {
            manager.StartClient();
            manager.networkAddress = IPInput.text;

            ClientScene.Ready(NetworkClient.connection);

            if (ClientScene.localPlayer == null)
            {
                ClientScene.AddPlayer();
            }
        }

        public void StartHost()
        {
            manager.StartHost();
        }

        public void StartServer()
        {
            manager.StartServer();
        }
    }
}